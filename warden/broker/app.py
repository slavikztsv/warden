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
from warden.broker.refusals import (
    AFTER_EXECUTE,
    AUDIT_UNAVAILABLE_MESSAGE,
    NOTHING_RAN,
    UNAUTHENTICATED_MESSAGE,
    after_the_fact,
)
from warden.broker.spine import (
    AUDIT_UNAVAILABLE,
    DENIED,
    UNAUTHENTICATED,
    Kind,
    Outcome,
    Spine,
)
from warden.broker.taint import TaintTracker


# The top-level packages `warden[mcp]` installs. An ImportError naming
# anything else out of warden/broker/mcp.py is a first-party defect, not a
# missing extra, and must not be reported as one.
_MCP_EXTRA = frozenset({"mcp", "mcp_types"})


def now() -> int:
    """Wall-clock seconds -- the default clock create_app falls back to
    when a caller does not inject one of its own."""
    return int(time.time())


def _render(outcome: Outcome) -> JSONResponse:
    """One Outcome, one response. Pure: rendering twice changes nothing,
    because every side effect already happened in the spine.

    The status codes and `error` keys are this surface's own; the MESSAGES are
    not. They come from warden/broker/refusals.py, which the MCP surface reads
    too, because the message is where the security-relevant content is: no
    exception text (three of the branches below used to render `str(exc)`
    straight out of Outcome.message, which put the audit log's path in a 503
    and an internal hostname in a 502), and a post-execute fault that says so
    rather than reading as retryable.
    """
    if outcome.kind is Kind.EXECUTED:
        return JSONResponse(
            {"content": outcome.result.content, "rows": outcome.result.rows}
        )
    if outcome.kind is Kind.UNAUTHENTICATED:
        return JSONResponse(
            {"error": UNAUTHENTICATED, "message": UNAUTHENTICATED_MESSAGE},
            status_code=401,
        )
    if outcome.kind in AUDIT_UNAVAILABLE:
        return JSONResponse(
            {"error": "audit_unavailable", "message": AUDIT_UNAVAILABLE_MESSAGE},
            status_code=503,
        )
    if outcome.kind is Kind.DESCRIBE_BACKEND_FAULT:
        return JSONResponse(
            {"error": "backend_error", "message": NOTHING_RAN}, status_code=502
        )
    if outcome.kind in AFTER_EXECUTE:
        # The action may already have happened and the taint update did not
        # run, so a retry would pass the same row budget twice. Same words, and
        # the same durable allow seq, as the MCP surface sends.
        return JSONResponse(
            {"error": "backend_error", "message": after_the_fact(outcome.audit_seq)},
            status_code=502,
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
    # Captured before anything can replace it, so the check below is against
    # what FastAPI itself installed rather than against a type name.
    pristine_lifespan = app.router.lifespan_context
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
            # Narrowed to the module that is actually optional. A typo'd
            # first-party import inside mcp.py raises ImportError too, and
            # reporting that as "install warden[mcp]" would send whoever hits
            # it to reinstall a package that is already there.
            if exc.name is not None and exc.name.split(".")[0] not in _MCP_EXTRA:
                raise
            raise ConfigError(
                "[mcp].enabled is true but the MCP extra is not installed; "
                "install warden[mcp]"
            ) from exc

        mount_mcp(app, spine=spine, catalog=catalog, config=mcp)

        # Asserted, not assumed: a second surface added later would overwrite
        # this and silently stop the first one's session manager from ever
        # starting -- which shows up as a request-time "Task group is not
        # initialized", not as a boot failure.
        if app.router.lifespan_context is not pristine_lifespan:
            raise ConfigError(
                "something already claimed this app's lifespan; the MCP "
                "session manager cannot be started without displacing it"
            )

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
