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

import contextlib
import time
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from warden.broker.audit import AuditLog
from warden.broker.config.catalog import ToolCatalog
from warden.broker.config.loader import ConfigError, McpConfig
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
            # The rule, where a proxy-aware client can read it without
            # parsing a body -- the same header broker/proxy.py sets on its
            # own refusals.
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
    # Its own parameter, never a BrokerComponents field. wiring.py's
    # as_proxy_kwargs() returns as_app_kwargs() verbatim and serve_proxy's
    # authorize_connect is keyword-only with no **kwargs, so a new key there
    # raises TypeError inside EVERY CONNECT -- at request time, with the
    # broker still reporting healthy. The proxy has no MCP surface and must
    # not be handed the config for one.
    mcp: McpConfig | None = None,
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

    if mcp is not None and mcp.enabled:
        # Imported here, not at module scope: the SDK is an optional extra
        # that drags in a second HTTP stack and opentelemetry-api, and a
        # deployment that never enables this surface must not need any of it
        # installed to start the broker.
        try:
            from warden.broker.mcp import mount_mcp
        except ImportError as exc:
            raise ConfigError(
                "[mcp].enabled is true but the MCP extra is not installed; "
                "install warden[mcp]"
            ) from exc

        mount_mcp(app, spine=spine, catalog=catalog, config=mcp)

        @contextlib.asynccontextmanager
        async def lifespan(_app):
            # A routed or mounted sub-app's lifespan never runs, so the
            # session manager -- whose run() owns the task group every
            # streamable-HTTP request is served inside -- has to be started by
            # the app it was attached to. Without this, the first request to
            # the surface raises "Task group is not initialized".
            async with app.state.mcp_session_manager.run():
                yield

        app.router.lifespan_context = lifespan

    @app.post("/v1/tools/{tool}/invoke")
    async def invoke(tool: str, request: Request) -> JSONResponse:
        # Authenticate BEFORE anything else about the request is read. A
        # credential that does not hold up must never cause the body to be
        # parsed -- see Spine.authenticate()'s docstring -- so this checks
        # for, and immediately returns on, a refusal before the one await
        # below ever runs.
        credential = _credential(request)
        authentication = spine.authenticate(credential, tool)
        if isinstance(authentication, Outcome):
            return _render(authentication)

        # The only await, and it is here rather than in the spine: past this
        # line the whole sequence is synchronous, so the snapshot-to-record
        # window cannot be interleaved by construction.
        args = await _parse_args(request)
        return _render(spine.handle_tool_call(credential, tool, args))

    return app
