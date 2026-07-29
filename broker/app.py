"""Agent-facing broker: the policy enforcement point.

Order of operations is the security property. Verify identity, gather context,
decide, make the decision durable, and only then act. Any failure at any stage
denies.

Two failure classes beyond policy denial are handled explicitly, because
letting either one surface as a bare 500 would route around the audited-
denial path this system exists to guarantee:

- backends.describe() can fail before any decision is reached (a malformed
  filter, missing args, ...). No decision happened, so this is audited as a
  deny under input.malformed, matching how an unrecognised tool is denied
  at the edge.
- backends.execute() can fail after the decision was already made and
  durably audited as an allow (an unreachable docstore, a non-2xx egress
  response, ...). The decision itself was sound and already logged, so this
  does not write a second decision record -- the original allow stands --
  it only reports that the action could not be completed.
"""

from __future__ import annotations

import hashlib
import time

import httpx
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

        body = await request.json()
        args = body.get("args", {})
        state = taint.snapshot(token.task_id)

        try:
            target = backends.describe(tool, args)
        except UnknownTool:
            # Deny-by-default at the edge: an unrecognised tool never reaches
            # the PDP, but is still audited under the capability rule.
            return _deny(
                audit, token, tool, args, ToolTarget(kind="unknown"), state,
                "tools.allowed", policy_digest,
            )
        except Exception as exc:
            # describe() failed before any decision could be reached (e.g. a
            # query_customers filter it cannot parse). There is no decision
            # to make, so this is audited as a deny under input.malformed
            # rather than escaping as an unhandled 500.
            return _backend_error(
                audit, token, tool, args, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest, str(exc),
            )

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
        except httpx.HTTPError as exc:
            # The allow decision above is already durable. Do not write a
            # second decision record for an execution-time failure -- the
            # original allow record stands as the true account of what was
            # authorized; only report that it could not be carried out.
            return JSONResponse(
                {"error": "backend_error", "message": str(exc)}, status_code=502
            )

        # rows is guaranteed non-negative here (it always comes from a
        # len()), but record_read() raises ValueError on a negative value
        # and this call happens after execution and after the audit record
        # is written -- clamp defensively so a future backend change can
        # never turn that into an unhandled 500 for an action that already
        # happened.
        taint.record_read(
            token.task_id, data_class=result.data_class, rows=max(result.rows, 0)
        )
        return JSONResponse({"content": result.content, "rows": result.rows})

    return app


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


def _backend_error(
    audit, token, tool, args, target, state, rule, policy_digest, message
) -> JSONResponse:
    failure = _write_deny_record(audit, token, tool, args, target, state, rule, policy_digest)
    if failure is not None:
        return failure
    return JSONResponse({"error": "backend_error", "message": message}, status_code=502)
