"""An MCP front door onto the same decision sequence.

This module RENDERS. It does not decide, it does not audit, and it does not
normalise: every one of those happens in the spine, which the HTTP surface
calls with the same arguments and gets the same Outcome from. A front door
that was free to interpret a request on its way past would be free to
disagree with the one the broker already has, and then "what did that call
do" would have two answers.

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

No exception text is rendered to a caller anywhere in here. The live sources
of one on these paths are the audit log's own filesystem errors and the
adapters' HTTP client, which between them name the audit path, internal
hostnames and the shape of the deployment's storage -- none of which belongs
in a model's context.

(`from mcp import ...` below reaches the installed SDK, not this module.
Python 3 has no implicit relative imports, so a module named `mcp` inside
`warden.broker` cannot shadow the top-level package for its own imports.)
"""

from __future__ import annotations

from typing import Any

from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from starlette.routing import Route

from warden.broker.schema_json import json_schema
from warden.broker.spine import AUDIT_UNAVAILABLE, DENIED, FAULT, Kind, Outcome

# Rendered in place of an exception message on every path that has one.
OPAQUE_FAULT = "The tool could not be completed. The failure was recorded."

AFTER_THE_FACT = (
    "The tool could not be completed, and the action it authorised may "
    "already have been performed. Do not repeat this call."
)

UNAUTHENTICATED_MESSAGE = (
    "Unauthenticated. Present a task token as an Authorization: Bearer "
    "credential."
)

AUDIT_UNAVAILABLE_MESSAGE = (
    "The broker cannot record decisions, so it is not making any. No tool ran."
)

# Every fault except DESCRIBE_BACKEND_FAULT left exactly one durable allow
# record for an action that may already have happened -- see FAULT's comment
# in spine.py. Derived rather than listed on purpose: a fault added to that
# set later renders as "do not repeat", which is the safe direction to be
# wrong in, instead of falling through to the generic branch at the bottom of
# render_call() and inviting a retry.
AFTER_EXECUTE = FAULT - {Kind.DESCRIBE_BACKEND_FAULT}

# The two protocol-error codes, taken from the SDK's own assigned set rather
# than picked out of the -32000..-32099 implementation range. -32001 in
# particular is NOT available: mcp_types binds it to REQUEST_TIMEOUT and the
# SDK's client GENERATES that code locally when a call times out, so a server
# answering with it sends something a client cannot tell from a timeout --
# which is the one condition every client retries.
UNAUTHENTICATED_CODE = types.INVALID_REQUEST
FAULT_CODE = types.INTERNAL_ERROR


def _credential(ctx: ServerRequestContext) -> str | None:
    """The raw Bearer credential off this request, or None.

    Not verified here: the spine verifies, and it does so inside the boundary
    that records the refusal. A surface that pre-screened credentials would
    own a second copy of that branch, free to drift from the HTTP one.

    `ctx.request` is the Starlette Request the transport attached to this
    message. It is None on transports that have no request (stdio), so the
    absence is a missing credential rather than an error.
    """
    request = getattr(ctx, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    header = headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ")


def _is_internal_schema_lookup(ctx: ServerRequestContext) -> bool:
    """True when this `tools/list` is the SDK asking itself, not a caller.

    On the 2026-07-28 protocol the SDK validates a `tools/call`'s
    `Mcp-Param-*` headers against the called tool's inputSchema, and it gets
    that schema by running THIS SERVER'S `tools/list` handler -- inline,
    before dispatching the call, on the same HTTP request. Left alone that
    turns one caller request into two spine decisions, and an unauthenticated
    call into TWO audit records for one probe: the listing's sentinel refusal
    and then the call's.

    The signal is exact rather than heuristic. On that path the SDK's inbound
    ladder REJECTS any request whose `Mcp-Method` header disagrees with its
    JSON-RPC method, before dispatch -- so a genuine `tools/list` can only
    ever arrive under `Mcp-Method: tools/list`, and a listing riding a request
    that says otherwise is by construction not the one the caller asked for.
    An absent header (the handshake-era transport, which does not do this
    lookup at all) reads as genuine.

    Answering it with an empty listing rather than an error is what keeps it
    quiet: the SDK then finds no schema, skips its header check, and logs
    nothing. Skipping that check costs warden nothing, because warden never
    reads those headers -- the spine decides on the body's arguments and
    executes on the same ones, so the two cannot disagree.
    """
    request = getattr(ctx, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return False
    routed = headers.get("mcp-method")
    return routed is not None and routed != "tools/list"


def _text(message: str, *, is_error: bool) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=is_error
    )


def render_call(outcome: Outcome) -> types.CallToolResult:
    """One Outcome, one result. Pure: every side effect already happened in
    the spine, so rendering twice changes nothing."""
    if outcome.kind is Kind.EXECUTED:
        return _text(outcome.result.content, is_error=False)
    if outcome.kind in DENIED:
        # A refusal, addressed to the model: it names the rule, and it arrives
        # as a tool error so the model can read it and pick something else.
        return _text(outcome.message, is_error=True)
    if outcome.kind in AFTER_EXECUTE:
        return _text(
            f"{AFTER_THE_FACT} (audit record {outcome.audit_seq})", is_error=True
        )
    if outcome.kind is Kind.DESCRIBE_BACKEND_FAULT:
        # Nothing ran and nothing was recorded, so this one is safe to retry
        # -- but it is still the broker's own bug, not the model's, and it has
        # nothing in it for a model to adapt to beyond "that did not work".
        return _text(OPAQUE_FAULT, is_error=True)
    if outcome.kind is Kind.UNAUTHENTICATED:
        # Not a tool error. There is nothing here for a model to adapt to: a
        # caller without authority has to be told to present a credential, and
        # that is a fact about the connection rather than about the tool.
        raise MCPError(code=UNAUTHENTICATED_CODE, message=UNAUTHENTICATED_MESSAGE)
    if outcome.kind in AUDIT_UNAVAILABLE:
        raise MCPError(code=FAULT_CODE, message=AUDIT_UNAVAILABLE_MESSAGE)
    raise MCPError(code=FAULT_CODE, message=OPAQUE_FAULT)


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


def mount_mcp(app, *, spine, catalog, config) -> None:
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

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        try:
            if _is_internal_schema_lookup(ctx):
                return types.ListToolsResult(tools=[])
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
            # `from None`: the chained context would be rendered by anything
            # that logs the error with a traceback, and the point of this
            # branch is that the caller learns nothing from it.
            raise MCPError(code=FAULT_CODE, message=OPAQUE_FAULT) from None

    async def on_call_tool(ctx, params) -> types.CallToolResult:
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
            raise MCPError(code=FAULT_CODE, message=OPAQUE_FAULT) from None

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
    app.router.routes.append(Route(config.path, endpoint=sub))
    # The sub-app's own lifespan is what would have started this, and a
    # mounted or routed sub-app's lifespan never runs. The app this was
    # attached to has to start it; see create_app.
    app.state.mcp_session_manager = server.session_manager
