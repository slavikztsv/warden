"""An MCP front door onto the same decision sequence.

This module RENDERS. It does not decide, it does not audit, and it does not
normalise: every one of those happens in the spine, which the HTTP surface
calls with the same arguments and gets the same Outcome from. A front door
that was free to interpret a request on its way past would be free to
disagree with the one the broker already has, and then "what did that call
do" would have two answers. The words both surfaces use live in
warden/broker/refusals.py for the same reason.

Both handlers are `async def` and call the spine DIRECTLY. That is a security
requirement, not a style choice. A sync handler would be run on a worker
thread, which puts the spine's taint snapshot and the read it authorises on
two different threads with a scheduling boundary between them -- and two
calls for one task that interleave there both read the same starting row
budget and both pass. The spine contains no `await`, so calling it inline
from the event loop cannot interleave at all.

Two renderings matter more than the rest.

A policy refusal comes back as a TOOL EXECUTION error (`is_error=True`)
rather than a protocol error, because a model that can read a refusal adapts
and one that receives a transport fault retries the identical call. That is
the difference between a task that finishes after being refused and a loop.

A failure that happened AFTER the action was carried out is phrased so it
cannot be read as retryable, and carries the seq of the durable allow record
that stands as the account of it. Those calls already did something -- sent
the mail, read the rows -- and the taint update never ran, so a retry would
pass the same budget check a second time on a budget that never moved.

No exception text is rendered to a caller anywhere in here, and the reason is
sharper than good manners: on the handshake-era transport an exception that
escapes a handler is put on the wire as `ErrorData(code=0, message=str(e))`
-- verbatim -- so the catch-alls below are the only thing between the audit
log's filesystem errors, the adapters' internal hostnames, and a model's
context window. They log server-side, because an MCPError is mapped straight
to the wire by the SDK's own ladder and never reaches its logging branch.

ONE UNAUDITED REFUSAL SHAPE, ACCEPTED DELIBERATELY -- AND CURRENTLY LATENT.
On the 2026-07-28 transport the SDK checks a `tools/call`'s `Mcp-Param-*`
headers against the called tool's schema before dispatch, and answers a
mismatch with a 400 that never reaches the spine. That would be the only
refusal this broker makes with no record. The check is kept anyway (see
`_is_internal_schema_lookup`) because it is routing integrity for
intermediaries and warden decides on the body's arguments either way.

Measured: today it validates nothing at all. The SDK only checks properties a
tool's inputSchema opts in via an `x-mcp-header` annotation, and
schema_json.json_schema() emits none -- so `_annotated_positions` is empty for
every warden tool and the rejection is unreachable. Keeping the lookup
answered from the catalog rather than with an empty list costs nothing now and
means the check works the day that vocabulary grows an opt-in. The unaudited
400 arrives with it; that is the trade, recorded before it can be paid by
accident.

(`from mcp import ...` below reaches the installed SDK, not this module.
Python 3 has no implicit relative imports, so a module named `mcp` inside
`warden.broker` cannot shadow the top-level package for its own imports.)
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp.shared.inbound import MCP_PROTOCOL_VERSION_HEADER
from mcp_types.version import (
    HANDSHAKE_PROTOCOL_VERSIONS,
    LATEST_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSIONS,
)
from starlette.routing import Route

from warden.broker.config.catalog import ToolCatalog
from warden.broker.config.loader import McpConfig
from warden.broker.refusals import (
    AFTER_EXECUTE,
    AUDIT_UNAVAILABLE_MESSAGE,
    NOTHING_RAN,
    UNAUTHENTICATED_MESSAGE,
    UNEXPECTED_FAULT,
    after_the_fact,
)
from warden.broker.schema_json import json_schema
from warden.broker.spine import AUDIT_UNAVAILABLE, DENIED, Kind, Outcome, Spine

logger = logging.getLogger(__name__)

# The three protocol-error codes, taken from the SDK's own assigned set
# rather than picked out of the -32000..-32099 implementation range by hand.
# -32001 in particular is NOT available: mcp_types binds it to
# REQUEST_TIMEOUT and the SDK's client GENERATES that code locally when a
# call times out, so a server answering with it sends something a client
# cannot tell from a timeout -- which is the one condition every client
# retries.
UNAUTHENTICATED_CODE = types.INVALID_REQUEST
FAULT_CODE = types.INTERNAL_ERROR
# What the SDK's own dispatcher would answer a truly-unsupported version
# with on the modern path -- see mcp_types.jsonrpc.UNSUPPORTED_PROTOCOL_VERSION
# / mcp.shared.inbound.ERROR_CODE_HTTP_STATUS (which maps it to HTTP 400,
# matching _refuse_era below). _EraGate uses the SAME code and status for a
# version-less or handshake-era request, because from a client's point of
# view the two failures are the same fact: this server does not serve the
# revision it asked for. `data.supported` is what the specification asks a
# modern-only server to return alongside it.
UNSUPPORTED_PROTOCOL_VERSION = types.UNSUPPORTED_PROTOCOL_VERSION


def _headers(ctx: ServerRequestContext) -> Mapping[str, str] | None:
    """This message's HTTP headers, or None if the transport has none.

    `ctx.request` is the Starlette Request the transport attached to the
    message. It is None on transports that have no request (stdio), which is
    why every reader below None-checks rather than assuming.
    """
    return getattr(getattr(ctx, "request", None), "headers", None)


def _credential(ctx: ServerRequestContext) -> str | None:
    """The raw Bearer credential off this request, or None.

    Not verified here: the spine verifies, and it does so inside the boundary
    that records the refusal. A surface that pre-screened credentials would
    own a second copy of that branch, free to drift from the HTTP one.
    """
    headers = _headers(ctx)
    if headers is None:
        return None
    header = headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ")


def _is_internal_schema_lookup(ctx: ServerRequestContext) -> bool:
    """True when this `tools/list` is the SDK asking itself, not a caller.

    On the 2026-07-28 transport the SDK validates a `tools/call`'s
    `Mcp-Param-*` headers against the called tool's inputSchema, and it gets
    that schema by running THIS SERVER'S `tools/list` handler -- inline,
    before dispatching the call, on the same HTTP request. Left alone that
    turns one caller request into two spine decisions, and one unauthenticated
    probe into TWO audit records: the listing's sentinel refusal and then the
    call's.

    THE ERA CHECK IS THE WHOLE GUARD, not a detail of it. The signal this
    rests on -- that a request's `Mcp-Method` header agrees with its JSON-RPC
    method, enforced pre-dispatch by `classify_inbound_request` -- exists on
    the modern transport ONLY. `StreamableHTTPSessionManager._handle_request`
    routes on `MCP-Protocol-Version` alone: absent, or any handshake-era
    version, goes to the legacy transport, which never calls that classifier
    and never looks at `Mcp-Method` at all. There, the header is unvalidated
    attacker input. Measured, before this check existed: a `tools/list` body
    with no protocol-version header and `Mcp-Method: tools/call` was served
    and left ZERO audit records, so an unauthenticated caller could probe the
    enforcement point indefinitely by adding one header -- defeating the
    property spine.py's docstring exists to state, that a call arriving
    without authority is recorded precisely because it is what a probe looks
    like. So: legacy era, or no version at all, is never an internal lookup.

    A `tools/list` on the modern era whose `Mcp-Method` says something else
    cannot be a caller's, because the classifier would have rejected it with
    HEADER_MISMATCH before reaching any handler.

    BELT AND BRACES: `_EraGate` (see `mount_mcp`) now refuses every
    handshake-era, version-less, or AMBIGUOUS (duplicated
    `MCP-Protocol-Version`) request over HTTP before it reaches the SDK's
    own routing at all -- which makes the branch below unreachable from any
    live request, but that is a property of the gate's current behaviour,
    not an inherent one of this function. Said precisely: unreachable
    BECAUSE the era gate refuses every handshake-era and ambiguous request,
    not unreachable on its own account. The "ambiguous" half of that is not
    hypothetical -- a request carrying `MCP-Protocol-Version` twice used to
    be exactly how a live caller reached this branch regardless of the gate:
    a folded (dict-style) header read let a modern LAST copy satisfy the
    gate while the SDK's own FIRST-match routing underneath still picked the
    handshake-era FIRST copy, so this handler could still be entered through
    the legacy transport the gate believed it had refused. The gate's header
    read was fixed to refuse any duplicate outright (see `_EraGate`) and to
    match the SDK's own first-match semantics for the single-copy case, but
    that fix lives one layer away from this function and could regress
    there without anything here changing. It stays anyway. Deleting it
    trades a redundant check for a SILENT reopening of the exact vector this
    function's docstring describes, the day someone removes or
    misconfigures the gate in front of it, or reintroduces a header-read
    disagreement like the one above; keeping it means that same regression
    instead fails LOUDLY, here, the next time a handshake-era request
    reaches this function directly (as it still can: this is a plain
    function, callable without going through the gate at all -- see
    `test_the_inline_lookup_is_answered_from_the_catalog_not_with_an_empty_list`,
    which does exactly that).
    """
    headers = _headers(ctx)
    if headers is None:
        return False
    version = headers.get("mcp-protocol-version")
    if version is None or version in HANDSHAKE_PROTOCOL_VERSIONS:
        # Redundant with _EraGate today; kept as the belt to its braces --
        # see the docstring above.
        return False
    routed = headers.get("mcp-method")
    return routed is not None and routed != "tools/list"


def _text(message: str, *, is_error: bool) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=is_error
    )


def render_call(outcome: Outcome) -> types.CallToolResult:
    """One Outcome, one result. Every side effect already happened in the
    spine, so this only chooses words -- and takes them from refusals.py, so
    the HTTP door says the same ones."""
    if outcome.kind is Kind.EXECUTED:
        return _text(outcome.result.content, is_error=False)
    if outcome.kind in DENIED:
        # A refusal, addressed to the model: it names the rule, and it arrives
        # as a tool error so the model can read it and pick something else.
        return _text(outcome.message, is_error=True)
    if outcome.kind in AFTER_EXECUTE:
        return _text(after_the_fact(outcome.audit_seq), is_error=True)
    if outcome.kind is Kind.DESCRIBE_BACKEND_FAULT:
        # Nothing ran and nothing was recorded, and the message says exactly
        # that. It is still the broker's own bug rather than the model's.
        return _text(NOTHING_RAN, is_error=True)
    if outcome.kind is Kind.UNAUTHENTICATED:
        # Not a tool error. There is nothing here for a model to adapt to: a
        # caller without authority has to be told to present a credential, and
        # that is a fact about the connection rather than about the tool.
        raise MCPError(code=UNAUTHENTICATED_CODE, message=UNAUTHENTICATED_MESSAGE)
    if outcome.kind in AUDIT_UNAVAILABLE:
        raise MCPError(code=FAULT_CODE, message=AUDIT_UNAVAILABLE_MESSAGE)
    # A Kind this surface has no branch for: a warden bug, and the only trace
    # of it will be this line, because the SDK puts an MCPError on the wire
    # without logging it.
    logger.error("no MCP rendering for outcome kind %r", outcome.kind)
    raise MCPError(code=FAULT_CODE, message=UNEXPECTED_FAULT)


def _transport_security(host: str) -> TransportSecuritySettings | None:
    """DNS-rebinding protection for the configured host, or the SDK's default.

    Returning None is not "off": it is what lets `streamable_http_app` apply
    its own rule, which is to turn protection ON with a loopback allow-list
    whenever it was given a loopback host -- and `host` defaults to
    127.0.0.1. An unconfigured surface therefore answers 421 to every request
    arriving under a real hostname, which is the failure a deployment wants to
    hit at once rather than the one where anything that can resolve a name
    reaches the broker.

    Note what the SDK's loopback list actually accepts: `127.0.0.1:*`,
    `localhost:*`, `[::1]:*` -- patterns that require a port, so even a bare
    `Host: 127.0.0.1` (port 80) is refused. Loopback without a port is not a
    configuration this can serve; name the host.

    No allowed_origins when a host IS configured, which refuses any request
    carrying an Origin header. The Origin check exists for browsers, and this
    is the agent-facing surface of an enforcement point: a page that can reach
    it is already the attack the check is named after.
    """
    if not host:
        return None
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host, f"{host}:*"],
    )


def _refuse_era_body() -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": UNSUPPORTED_PROTOCOL_VERSION,
            "message": (
                "Unsupported protocol version. This server serves the "
                f"{LATEST_PROTOCOL_VERSION} revision only."
            ),
            "data": {"supported": [LATEST_PROTOCOL_VERSION]},
        },
    }).encode("utf-8")


async def _refuse_era(send) -> None:
    """The -32022 refusal, written directly over ASGI.

    This runs in front of the SDK's own routing -- there is no Starlette
    Request or Response built for it yet, only the raw `send` callable -- so
    the two ASGI messages that make up an HTTP response are assembled by
    hand instead of going through FastAPI/Starlette's usual response
    classes.
    """
    await send({
        "type": "http.response.start",
        "status": 400,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": _refuse_era_body()})


# Encoded once, from the SDK's own constant -- not hand-spelled -- so this
# and `StreamableHTTPSessionManager._handle_request`'s
# `header = MCP_PROTOCOL_VERSION_HEADER.encode("ascii")` can never name two
# different header strings. ASGI header names arrive pre-lowercased by a
# conforming server (the ASGI spec requires it), which is what a bare `==`
# against raw scope bytes below relies on -- the same reliance the SDK's own
# read has.
_PROTOCOL_VERSION_HEADER_BYTES = MCP_PROTOCOL_VERSION_HEADER.encode("ascii")


class _EraGate:
    """Refuses every protocol revision but the modern one, before the SDK
    routes the request at all.

    `StreamableHTTPSessionManager._handle_request` reads `MCP-Protocol-
    Version` straight off the raw ASGI scope to pick between two transports:
    absent, or any of `HANDSHAKE_PROTOCOL_VERSIONS`, goes to a legacy leg
    that does not validate `Mcp-Method` against the request body and whose
    dispatcher puts `str(exc)` on the wire verbatim (see this module's
    docstring). Both of those are reachable by omitting one header, which
    makes the WEAKER of the two enforcement paths the default -- selectable
    by the party this broker exists to contain. An enforcement point cannot
    let the party it contains choose which of its own code paths handles the
    request, so this wraps the mounted sub-app rather than living in a
    handler: by the time any handler runs, the SDK has already made that
    choice, and there would be nothing left here to refuse.

    Refusing is spec-conformant, not a new restriction invented for this
    deployment: dual-era support is a MAY in the specification, not a MUST,
    and -32022 with a `supported` list in `data` is what a modern-only
    server is asked to answer a version it does not serve with. It costs a
    real client nothing either -- the SDK's own `Client` carries
    `MCP-Protocol-Version: 2026-07-28` on every request of a session,
    including the opening one, so "absent" and "handshake-era" are exactly
    the requests this SDK's own client never sends.

    The refusal is audited. `Spine.record_handshake_refusal` writes a
    sentinel record before `_refuse_era` answers, which -- like
    broker/proxy.py's equivalent for a non-CONNECT probe -- lets a caller
    with no credential at all, not even an invalid one, drive a write to the
    audit log. That is the deliberate trade recorded in the audit-evasion
    vector this closes: an unrecorded refusal is what let a caller probe the
    enforcement point indefinitely by adding one header, and a few sentinel
    rows from an unauthenticated party are a smaller cost than a probe that
    leaves no trace.

    A CLASS, deliberately, not a closure returning a plain function.
    `starlette.routing.Route.__init__` decides how to treat its `endpoint`
    by `inspect.isfunction`/`inspect.ismethod`: a plain function is assumed
    to be `func(request) -> response` and gets wrapped in
    `request_response()`, which calls it with a single `Request` rather than
    `(scope, receive, send)` -- the exact three this needs, and a
    `functools.partial` does not dodge the check either, since Starlette
    unwraps those to the function underneath before testing. An instance of
    a class with `__call__` is neither a function nor a method, so Starlette
    falls through to its other branch and treats it as what it is: an ASGI
    app in its own right, exactly like the sub-app it wraps.

    THE HEADER READ MUST AGREE WITH THE SDK'S OWN, EXACTLY, OR THIS GATE IS
    THE SAME BUG ONE LAYER UP. `StreamableHTTPSessionManager._handle_request`
    reads the version with `next((v.decode(...) for k, v in scope["headers"]
    if k == header), None)` -- FIRST match. A dict comprehension over the
    same list keeps the LAST match instead. Sent twice, with a handshake-era
    value first and a modern value second, those two reads disagree: this
    gate would see "modern" and wave the request through, the SDK's routing
    would see "handshake-era" underneath it and route to the legacy
    transport anyway -- the exact leg with no `Mcp-Method` validation and
    `str(exc)` on the wire, reachable again through the gate meant to close
    it off. Measured. So the single-occurrence read below uses `next(...)`
    against the raw scope, matching the SDK's read byte for byte, not a
    folded mapping -- removing the disagreement by construction rather than
    by a guard that could itself drift out of sync later.

    A DUPLICATE IS REFUSED OUTRIGHT, independent of what either copy says.
    No conforming client sends `MCP-Protocol-Version` twice; a second copy is
    a disagreement attempt against whichever reader looks at it, and
    warden's stance is that ambiguity refuses rather than picks a side --
    the same discipline `mcp.shared.inbound.find_duplicated_routing_header`
    applies one layer downstream, inside the modern transport's own
    request-shape ladder. That function was not reused here: it checks THREE
    routing headers (`Mcp-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) against
    decoded string pairs, and this gate routes on exactly one, read off the
    raw scope before any decoding happens for the other two -- duplicates of
    the other two remain that ladder's job, once a single-valued
    `MCP-Protocol-Version` has let a request reach it. Refusing on ANY
    duplicate -- including two copies that both name the modern version --
    is deliberate: a client with a legitimate reason to send this header
    twice does not exist, so there is no served case being narrowed, only an
    ambiguous one being closed.
    """

    def __init__(self, inner, *, spine: Spine) -> None:
        self._inner = inner
        self._spine = spine

    async def __call__(self, scope, receive, send) -> None:
        raw_headers = scope.get("headers", [])
        occurrences = [v for k, v in raw_headers if k == _PROTOCOL_VERSION_HEADER_BYTES]
        if len(occurrences) > 1:
            self._spine.record_handshake_refusal("mcp.unsupported_protocol")
            await _refuse_era(send)
            return
        version = occurrences[0].decode("latin-1") if occurrences else None
        if version is None or version not in MODERN_PROTOCOL_VERSIONS:
            # Not "in HANDSHAKE_PROTOCOL_VERSIONS": that only names the four
            # revisions the SDK recognises as handshake-era, and leaves a gap
            # for the versions it recognises as neither -- an unserved future
            # revision (e.g. "2027-01-01") or outright garbage ("not-a-
            # version"). Those are not "absent" and not "handshake-era", so
            # the old condition let them fall through to `self._inner`,
            # which routes them into the SDK's own modern entry
            # (`classify_inbound_request`, default `supported_modern_versions
            # =MODERN_PROTOCOL_VERSIONS`) for a STRUCTURALLY IDENTICAL -32022
            # refusal -- same code, same HTTP 400 -- with no spine call and
            # therefore no audit record. Testing against MODERN_PROTOCOL_
            # VERSIONS instead closes that gap by construction: it is the
            # exact set `classify_inbound_request` itself accepts (verified
            # against mcp.shared.inbound's default), so nothing this SDK's
            # modern transport would serve is refused here by mistake, and
            # everything it would refuse is now refused WITH a record.
            self._spine.record_handshake_refusal("mcp.unsupported_protocol")
            await _refuse_era(send)
            return
        await self._inner(scope, receive, send)


def mount_mcp(
    app: FastAPI, *, spine: Spine, catalog: ToolCatalog, config: McpConfig
) -> None:
    """Mounts the surface onto an existing app, sharing its one spine.

    Takes the spine it was given rather than reading `app.state.spine`, so the
    thing this surface decides with is the thing the caller wired -- there is
    no arrangement in which the two are different objects.
    """

    def _tool(name: str) -> types.Tool:
        entry = catalog.entry(name)
        # `or None` rather than "": an absent title is absent, not blank. A
        # catalog reaching a live MCP deployment has both (`warden config
        # check` refuses one that does not, once this surface is enabled).
        return types.Tool(
            name=name,
            title=entry.title or None,
            description=entry.description or None,
            input_schema=json_schema(entry.schema),
        )

    async def on_list_tools(
        ctx: ServerRequestContext, params
    ) -> types.ListToolsResult:
        try:
            if _is_internal_schema_lookup(ctx):
                # The SDK's own pre-dispatch schema lookup, answered from the
                # catalog: no spine call, so no second decision and no second
                # audit record, and no token scoping either -- because this
                # result is consumed inside the SDK to validate the call's
                # `Mcp-Param-*` headers against the schema and is never
                # written to the wire. Answering it with an empty list instead
                # would disable that routing-integrity check on every call.
                return types.ListToolsResult(
                    tools=[_tool(name) for name in sorted(catalog.names())]
                )
            outcome = spine.list_tools(_credential(ctx))
            if outcome.kind is Kind.LISTED:
                return types.ListToolsResult(
                    tools=[_tool(name) for name in outcome.tools]
                )
            if outcome.kind in AUDIT_UNAVAILABLE:
                raise MCPError(code=FAULT_CODE, message=AUDIT_UNAVAILABLE_MESSAGE)
            # A listing has no is_error channel, so a refusal has to be a
            # protocol error. An empty list would be indistinguishable from a
            # token that legitimately grants nothing.
            raise MCPError(code=UNAUTHENTICATED_CODE, message=UNAUTHENTICATED_MESSAGE)
        except MCPError:
            raise
        except Exception:
            # Logged here because nothing downstream will: the SDK maps an
            # MCPError straight to the wire and never reaches its own
            # logger.exception branch. `from None` keeps the chained context
            # out of anything that formats this error for a caller.
            logger.exception("MCP tools/list failed")
            raise MCPError(code=FAULT_CODE, message=UNEXPECTED_FAULT) from None

    async def on_call_tool(ctx: ServerRequestContext, params) -> types.CallToolResult:
        try:
            # `arguments: null` is how a client invokes a tool with no
            # arguments, so it normalises to {} -- matching what the HTTP body
            # parser does with a missing "args". None is reserved in the spine
            # for a body that did not parse at all, and this transport cannot
            # produce one: a body that does not parse never reaches a handler.
            arguments: dict[str, Any] = params.arguments or {}
            return render_call(
                spine.handle_tool_call(_credential(ctx), params.name, arguments)
            )
        except MCPError:
            raise
        except Exception:
            logger.exception("MCP tools/call failed")
            raise MCPError(code=FAULT_CODE, message=UNEXPECTED_FAULT) from None

    server = Server("warden", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    sub = server.streamable_http_app(
        streamable_http_path=config.path,
        # No sessions. A session id would be a second way to name a caller
        # alongside the token, and the spine's whole state is keyed on the
        # token's task_id -- so a session could only ever add a channel that
        # decides nothing and can disagree.
        stateless_http=True,
        host=config.host or "127.0.0.1",
        transport_security=_transport_security(config.host),
    )
    # A Route, not a Mount. `streamable_http_app` registers its endpoint as a
    # Route at `streamable_http_path`, and a Starlette Mount strips its own
    # prefix off the path before the sub-app matches -- so mounting at
    # `config.path` makes the endpoint reachable only at `<path>/`, with a bare
    # `<path>` answered by a 307 that MCP clients do not follow (measured: the
    # SDK's own client fails the connection). Routing the exact configured path
    # into a sub-app that expects that same path leaves the endpoint where
    # every client is configured to look for it.
    #
    # POST only, which is everything this surface needs while it is stateless.
    # An unauthenticated GET opens the protocol's standalone SSE stream and
    # holds the connection open indefinitely, with no record of it anywhere --
    # measured: no response in six seconds. Nothing wants it: the SDK's client
    # returns from handle_get_stream immediately unless it holds a session id,
    # `stateless_http=True` never issues one, DELETE (session teardown) is
    # gated the same way, and the modern transport already 405s non-POST
    # itself. GET and DELETE become load-bearing the moment anyone chooses
    # `stateless_http=False` above, so the two go together.
    #
    # `sub` wrapped in `_EraGate`, not mounted bare: the gate has to see
    # every request before the SDK's own routing does, and by the time a
    # request reaches anything mounted AS this sub-app that routing has
    # already happened.
    app.router.routes.append(
        Route(config.path, endpoint=_EraGate(sub, spine=spine), methods=["POST"])
    )
    # The sub-app's own lifespan is what would have started this, and a
    # mounted or routed sub-app's lifespan never runs. The app this was
    # attached to has to start it; see create_app.
    app.state.mcp_session_manager = server.session_manager
