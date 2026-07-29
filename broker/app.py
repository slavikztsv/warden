"""Agent-facing broker: the policy enforcement point.

Order of operations is the security property. Verify identity, gather context,
decide, make the decision durable, and only then act. Any failure at any stage
denies.

Several failure classes beyond an explicit policy denial are handled
explicitly, because letting any of them surface as a bare 500 would route
around the audited-denial path this system exists to guarantee, or would
let the response body lie about what happened:

- A malformed request body (not JSON, not an object, or an "args" that
  isn't an object) never reaches describe() at all. No decision was
  possible, so it is audited as a deny under input.malformed.
- The args for a tool are shape-checked *before* describe() is called, so
  describe() (which decides what gets audited and policy-checked) and
  execute() (which acts) are guaranteed to interpret the same args the
  same way. Without this, the two stages can disagree about what the
  target even is -- e.g. a bare string passed where send_email expects a
  list of recipients gets read character-by-character by one stage and as
  the original string by the other.
- A remaining describe() failure that shape-checking didn't catch (e.g. a
  query_customers filter value of the right type but not parseable) is
  still the agent's doing, so it is likewise audited as a deny under
  input.malformed. A describe() failure that is *not* attributable to the
  request (a server bug: AttributeError, sqlite3.Error, ...) is not -- it
  is reported as a plain backend fault with nothing recorded against the
  agent, since no decision was avoided because of anything the agent did.
- backends.execute() can fail after the decision was already made and
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

from broker.audit import AuditLog
from broker.backends import Backends, ToolTarget, UnknownTool
from broker.identity import TokenInvalid, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.taint import TaintTracker


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


def _args_are_well_shaped(tool: str, args: dict) -> bool:
    """Per-tool required-argument shape check, run before describe() so
    describe() and execute() are guaranteed to see the same, correctly
    shaped args. Tools not in this table are left to describe()'s
    UnknownTool handling."""
    if tool == "read_document":
        return isinstance(args.get("doc_id"), str) and args["doc_id"] != ""
    if tool == "query_customers":
        return isinstance(args.get("filter"), str)
    if tool == "http_fetch":
        body = args.get("body")
        return (
            isinstance(args.get("url"), str)
            and args["url"] != ""
            and (body is None or isinstance(body, str))
        )
    if tool == "send_email":
        to = args.get("to")
        return (
            isinstance(to, list)
            and all(isinstance(item, str) for item in to)
            and isinstance(args.get("subject"), str)
            and isinstance(args.get("body"), str)
        )
    return True


def create_app(
    *,
    verifier: Verifier,
    pdp: PolicyDecisionPoint,
    taint: TaintTracker,
    audit: AuditLog,
    backends: Backends,
    policy_digest: str,
) -> FastAPI:
    app = FastAPI(title="warden broker")

    @app.post("/v1/tools/{tool}/invoke")
    async def invoke(tool: str, request: Request) -> JSONResponse:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return JSONResponse(
                {"error": "unauthenticated", "message": "Bearer token required."},
                status_code=401,
            )
        try:
            token = verifier.verify(header.removeprefix("Bearer "), now=now())
        except TokenInvalid as exc:
            return JSONResponse(
                {"error": "unauthenticated", "message": str(exc)}, status_code=401
            )

        state = taint.snapshot(token.task_id)

        args = await _parse_args(request)
        if args is None:
            return _deny(
                audit, token, tool, {}, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest,
            )

        if not _args_are_well_shaped(tool, args):
            return _deny(
                audit, token, tool, args, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest,
            )

        try:
            target = backends.describe(tool, args)
        except UnknownTool:
            # Deny-by-default at the edge: an unrecognised tool never reaches
            # the PDP, but is still audited under the capability rule.
            return _deny(
                audit, token, tool, args, ToolTarget(kind="unknown"), state,
                "tools.allowed", policy_digest,
            )
        except ValueError:
            # A client-caused describe() failure the shape check above
            # doesn't catch (e.g. a query_customers filter value of the
            # right type but not parseable). Still the agent's fault.
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
            result = backends.execute(tool, args)
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
    )
