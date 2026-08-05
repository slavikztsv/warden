"""Agent-facing broker: the policy enforcement point.

Order of operations is the security property. Verify identity, gather context,
decide, make the decision durable, and only then act. Any failure at any stage
denies.

Several failure classes beyond an explicit policy denial are handled
explicitly, because letting any of them surface as a bare 500 would route
around the audited-denial path this system exists to guarantee, or would
let the response body lie about what happened:

- A missing, malformed, or expired token is refused with a 401 AND
  recorded, with sentinel principal fields, because a call arriving
  without authority is exactly what a probe looks like and an unrecorded
  refusal makes it indistinguishable from a run that never happened.
- A malformed request body (not JSON, not an object, or an "args" that
  isn't an object) never reaches describe() at all. No decision was
  possible, so it is audited as a deny under input.malformed.
- The args for a tool are shape-checked *before* describe() is called, so
  describe() (which decides what gets audited and policy-checked) and
  execute() (which acts) are guaranteed to interpret the same args the
  same way. Without this, the two stages can disagree about what the
  target even is -- e.g. a bare string passed where a tool's schema expects
  a list of recipients gets read character-by-character by one stage and as
  the original string by the other.
- A remaining describe() failure that shape-checking didn't catch (e.g. a
  filter value of the right type but not parseable, or an arg an adapter
  dereferences that the schema left optional) is still the agent's doing,
  so it is likewise audited as a deny under input.malformed. This set is
  ValueError, KeyError, TypeError and IndexError -- widened from ValueError
  alone because moving argument shape-checking into config makes it
  OMISSIBLE: an adapter can read an arg its schema does not require, and
  that reads as KeyError, not ValueError. Measured before this widening: a
  502 with zero audit records, an agent probing with no trace, the same
  defect _refuse_unauthenticated exists to close on the auth path. A
  describe() failure that is *not* attributable to the request (a server
  bug: AttributeError, sqlite3.Error, ...) is not -- it is reported as a
  plain backend fault with nothing recorded against the agent, since no
  decision was avoided because of anything the agent did.
- catalog.execute() can fail after the decision was already made and
  durably audited as an allow (an unreachable docstore, a non-2xx egress
  response, an unexpected backend bug, ...). The decision itself was sound
  and already logged, so this does not write a second decision record --
  the original allow stands -- it only reports that the action could not
  be completed. This guard is intentionally broad (not narrowed to e.g.
  httpx errors): nothing may escape this call site once an allow is
  durable, or the audit log ends up asserting an authorized action that
  never actually happened.
- taint.record_read() rejects a negative row count rather than silently
  under-counting a security budget (that invariant belongs to taint.py:
  reject over clamp). That call happens after execution and after the
  audit record is written, so a rejection here is reported as a backend
  fault with the taint state left untouched, rather than crashing an
  already-authorized, already-executed, already-audited request.
"""

from __future__ import annotations

import hashlib
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from warden.broker.adapters.base import ToolTarget, UnknownTool
from warden.broker.audit import AuditLog
from warden.broker.config.catalog import ToolCatalog
from warden.broker.identity import TokenInvalid, Verifier
from warden.broker.pdp import PolicyDecisionPoint
from warden.broker.taint import TaintTracker


def now() -> int:
    """Indirection so tests can control the clock."""
    return int(time.time())


def _args_digest(args: dict) -> str:
    import json

    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _parse_args(request: Request) -> dict | None:
    """Defensively parses the request body. Returns the "args" object on
    success, or None if the body is not JSON, not a JSON object, or has an
    "args" that isn't itself a JSON object -- any of which means there is
    no well-formed request to make a decision about."""
    try:
        body = await request.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    args = body.get("args", {})
    if not isinstance(args, dict):
        return None
    return args


def create_app(
    *,
    verifier: Verifier,
    pdp: PolicyDecisionPoint,
    taint: TaintTracker,
    audit: AuditLog,
    catalog: ToolCatalog,
    policy_digest: str,
) -> FastAPI:
    app = FastAPI(title="warden broker")

    @app.post("/v1/tools/{tool}/invoke")
    async def invoke(tool: str, request: Request) -> JSONResponse:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return _refuse_unauthenticated(
                audit, tool, "Bearer token required.", policy_digest
            )
        try:
            token = verifier.verify(header.removeprefix("Bearer "), now=now())
        except TokenInvalid as exc:
            return _refuse_unauthenticated(audit, tool, str(exc), policy_digest)

        args = await _parse_args(request)
        # Snapshot AFTER the final await. Everything from here to record_read
        # is synchronous, so under a single worker the read-decide-record
        # sequence cannot interleave with another request for the same task.
        # Taking it earlier put an await inside the critical section and made
        # the row bound racy on one event loop, never mind multiple workers.
        state = taint.snapshot(token.task_id)

        if args is None:
            return _deny(
                audit, token, tool, {}, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest,
            )

        if not catalog.validate(tool, args):
            return _deny(
                audit, token, tool, args, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest,
            )

        try:
            target = catalog.describe(tool, args)
        except UnknownTool:
            # Deny-by-default at the edge: an unrecognised tool never reaches
            # the PDP, but is still audited under the capability rule.
            return _deny(
                audit, token, tool, args, ToolTarget(kind="unknown"), state,
                "tools.allowed", policy_digest,
            )
        except (ValueError, KeyError, TypeError, IndexError):
            # Client-caused describe() failures the schema did not catch: a
            # filter value of the right type but not parseable, or an arg the
            # adapter dereferences that the schema left optional. KeyError is
            # NOT ValueError, so before this it fell into the backend-fault
            # branch below -- 502, and nothing recorded against the agent,
            # which is an agent probing with no trace.
            return _deny(
                audit, token, tool, args, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest,
            )
        except Exception as exc:
            # A genuine backend/server fault, not the agent's doing. No
            # decision was avoided because of anything the agent did, so
            # nothing is recorded against it -- just report the fault.
            return _backend_fault(str(exc))

        decision = pdp.decide(
            {
                "principal": {
                    "agent_id": token.agent_id,
                    "task_id": token.task_id,
                    "purpose": token.purpose,
                    "allowed_tools": list(token.allowed_tools),
                    "counterparties": list(token.counterparties),
                },
                "action": {
                    "type": "tool_call",
                    "tool": tool,
                    "args_digest": _args_digest(args),
                },
                "target": target.as_dict(),
                "task_state": state,
            }
        )

        if not decision.allow:
            return _deny(
                audit, token, tool, args, target, state, decision.rule, policy_digest
            )

        try:
            audit.append(
                task_id=token.task_id,
                agent_id=token.agent_id,
                purpose=token.purpose,
                action={"type": "tool_call", "tool": tool},
                target=target.as_dict(),
                args_digest=_args_digest(args),
                decision="allow",
                rule=decision.rule,
                task_state=state,
                policy_bundle_digest=policy_digest,
            )
        except OSError as exc:
            # If it cannot be logged, it cannot be done.
            return JSONResponse(
                {"error": "audit_unavailable", "message": str(exc)}, status_code=503
            )

        try:
            result = catalog.execute(tool, args)
        except Exception as exc:
            # The allow decision above is already durable. Do not write a
            # second decision record for an execution-time failure -- the
            # original allow record stands as the true account of what was
            # authorized; only report that it could not be carried out.
            # Deliberately broad: nothing may escape this call site once an
            # allow is durable.
            return _backend_fault(str(exc))

        try:
            taint.record_read(
                token.task_id, data_class=result.data_class, rows=result.rows
            )
        except ValueError as exc:
            # taint.py rejects a negative row count rather than silently
            # under-counting a security budget; honour that by surfacing
            # the fault instead of clamping it away, and leave the taint
            # state untouched. The already-durable allow record stands.
            return _backend_fault(str(exc))

        return JSONResponse({"content": result.content, "rows": result.rows})

    return app


UNAUTHENTICATED = "unauthenticated"


def _refuse_unauthenticated(
    audit: AuditLog, tool: str, message: str, policy_digest: str
) -> JSONResponse:
    """Refuses a call carrying no usable token -- and records it.

    A missing, malformed, or expired token on the tool API is what an attempt
    to act without authority looks like, and it left ZERO trace: three such
    requests produced three 401s and an empty audit log, so a probe was
    indistinguishable from a run that never happened. This is the same defect
    the proxy had, fixed there three times, and its own comment calls the
    equivalent record "the single most valuable record the proxy produces".
    Denying and recording are separate requirements; a system whose demo
    climax is replaying an attack path cannot have an unrecorded refusal.

    There is no token, so there is no principal to attribute this to: the
    fields carry the same sentinels broker/proxy.py's _audit_refusal uses
    (task_id "-", agent_id "unauthenticated", purpose "-"), which the replay
    renderer already knows how to display. The request body is deliberately
    never read -- nothing about an unauthenticated caller's claimed arguments
    is trustworthy, and parsing it would only add a failure mode. The tool
    name comes from the path and is recorded as attempted, not as validated.
    """
    failure = None
    try:
        audit.append(
            task_id="-",
            agent_id=UNAUTHENTICATED,
            purpose="-",
            action={"type": "tool_call", "tool": tool},
            target=ToolTarget(kind="unknown").as_dict(),
            args_digest="sha256:none",
            decision="deny",
            rule=UNAUTHENTICATED,
            task_state={"data_classes_held": [], "rows_returned_so_far": 0},
            policy_bundle_digest=policy_digest,
        )
    except OSError as exc:
        # Same rule as every other refusal on this surface: if it cannot be
        # logged, it is reported as unavailable rather than quietly refused.
        # (broker/proxy.py deliberately differs -- it swallows the failure and
        # still refuses -- because a tunnel refusal must happen even when it
        # cannot be recorded. The asymmetry is documented in docs/THREAT_MODEL.md.)
        failure = JSONResponse(
            {"error": "audit_unavailable", "message": str(exc)}, status_code=503
        )
    if failure is not None:
        return failure
    return JSONResponse(
        {"error": UNAUTHENTICATED, "message": message}, status_code=401
    )


def _backend_fault(message: str) -> JSONResponse:
    """A backend-side failure not attributable to the agent: nothing is
    audited (no decision was avoided because of anything the agent did),
    just reported."""
    return JSONResponse({"error": "backend_error", "message": message}, status_code=502)


def _write_deny_record(
    audit, token, tool, args, target, state, rule, policy_digest
) -> JSONResponse | None:
    """Writes a deny record. Returns an audit_unavailable response if the
    write itself fails, else None."""
    try:
        audit.append(
            task_id=token.task_id,
            agent_id=token.agent_id,
            purpose=token.purpose,
            action={"type": "tool_call", "tool": tool},
            target=target.as_dict(),
            args_digest=_args_digest(args),
            decision="deny",
            rule=rule,
            task_state=state,
            policy_bundle_digest=policy_digest,
        )
        return None
    except OSError as exc:
        return JSONResponse(
            {"error": "audit_unavailable", "message": str(exc)}, status_code=503
        )


def _deny(audit, token, tool, args, target, state, rule, policy_digest) -> JSONResponse:
    failure = _write_deny_record(audit, token, tool, args, target, state, rule, policy_digest)
    if failure is not None:
        return failure
    return JSONResponse(
        {
            "error": "policy_denied",
            "rule": rule,
            "message": f"Denied by policy rule {rule}.",
        },
        status_code=403,
        # The rule, where a proxy-aware client can read it without parsing a
        # body -- the same header broker/proxy.py sets on its own refusals.
        headers={"X-Warden-Rule": rule},
    )
