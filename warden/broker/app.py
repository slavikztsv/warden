"""Agent-facing broker: the policy enforcement point.

This module is the HTTP surface only: it authenticates nothing and decides
nothing itself. It pulls a bearer credential and a JSON body off the wire,
hands them to warden.broker.spine.Spine -- which holds the actual security
property, the verify -> snapshot -> validate -> decide -> record -> execute
sequence -- and renders whatever Outcome comes back into a response. The
reasoning behind each failure branch (a malformed body, a describe()
failure, an audit write that cannot be made durable, ...) moved to spine.py
along with the code that handles it; see that module's docstring and its
inline comments for why each one denies, faults, or reports unavailable the
way it does.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from warden.broker.audit import AuditLog
from warden.broker.config.catalog import ToolCatalog
from warden.broker.identity import Verifier
from warden.broker.pdp import PolicyDecisionPoint
from warden.broker.spine import (
    AUDIT_UNAVAILABLE,
    DENIED,
    FAULT,
    UNAUTHENTICATED,
    Kind,
    Outcome,
    Spine,
)
from warden.broker.taint import TaintTracker


def now() -> int:
    """Wall-clock seconds -- the default clock create_app falls back to
    when a caller does not inject one of its own."""
    return int(time.time())


def _render(outcome: Outcome) -> JSONResponse:
    """One Outcome, one response. Pure: rendering twice changes nothing,
    because every side effect already happened in the spine."""
    if outcome.kind is Kind.EXECUTED:
        return JSONResponse(
            {"content": outcome.result.content, "rows": outcome.result.rows}
        )
    if outcome.kind is Kind.UNAUTHENTICATED:
        return JSONResponse(
            {"error": UNAUTHENTICATED, "message": outcome.message}, status_code=401
        )
    if outcome.kind in AUDIT_UNAVAILABLE:
        return JSONResponse(
            {"error": "audit_unavailable", "message": outcome.message}, status_code=503
        )
    if outcome.kind in FAULT:
        return JSONResponse(
            {"error": "backend_error", "message": outcome.message}, status_code=502
        )
    if outcome.kind in DENIED:
        return JSONResponse(
            {
                "error": "policy_denied",
                "rule": outcome.rule,
                "message": outcome.message,
            },
            status_code=403,
            headers={"X-Warden-Rule": outcome.rule},
        )
    raise ValueError(f"no HTTP rendering for {outcome.kind}")


async def _parse_args(request: Request) -> dict | None:
    """Returns the "args" object, or None if the body is not JSON, not an
    object, or has an "args" that is not itself an object -- any of which
    means there is no well-formed request to decide about."""
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


def _credential(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ")


def create_app(
    *,
    verifier: Verifier,
    pdp: PolicyDecisionPoint,
    taint: TaintTracker,
    audit: AuditLog,
    catalog: ToolCatalog,
    policy_digest: str,
    clock: Callable[[], int] | None = None,
) -> FastAPI:
    app = FastAPI(title="warden broker")
    spine = Spine(
        verifier=verifier,
        pdp=pdp,
        taint=taint,
        audit=audit,
        catalog=catalog,
        policy_digest=policy_digest,
        clock=clock or now,
    )
    # Reachable by any surface mounted onto this app later. There is exactly
    # one spine per app, which is what makes two front doors incapable of
    # deciding differently.
    app.state.spine = spine

    @app.post("/v1/tools/{tool}/invoke")
    async def invoke(tool: str, request: Request) -> JSONResponse:
        # The only await, and it is here rather than in the spine: past this
        # line the whole sequence is synchronous, so the snapshot-to-record
        # window cannot be interleaved by construction.
        credential = _credential(request)
        args = None if credential is None else await _parse_args(request)
        return _render(spine.handle_tool_call(credential, tool, args))

    return app
