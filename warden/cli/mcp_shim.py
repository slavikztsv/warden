"""A stdio front end that forwards to a broker's MCP surface.

This process runs inside the agent's own process tree, launched by whatever
config the agent reads. Treat it as untrusted: it holds one task token, it
holds no key, it knows no control-plane address, and it makes no decision.
Everything it could be tricked into doing has a rule below.

It contains no policy and no catalog. Every question it is asked is asked
again upstream, which is what keeps it from becoming a second place where a
call could be interpreted.

SIX API DEVIATIONS FROM THE ORIGINAL BRIEF, EACH CHECKED AGAINST THE
INSTALLED mcp==2.0.0 / mcp_types==2.0.0 SOURCE AND A RUNNING PROBE:

1. ``Client(*streams)`` is not the constructor (Task 11 already found this).
   It is ``Client(server: Server | MCPServer | Transport | str, *, ...)`` --
   one positional argument. ``streamable_http_client(url, http_client=...)``
   is an async context manager yielding ``(read, write)``, which satisfies
   the ``Transport`` protocol, so the working call is
   ``Client(streamable_http_client(url, http_client=...), cache=None)``.

2. ``streamable_http_client`` has no ``headers=`` keyword (Task 11 again).
   Its signature is ``(url, *, http_client=None, terminate_on_close=True)``;
   headers belong on the ``httpx2.AsyncClient`` handed in as ``http_client``.

3. THE CACHE CONTROL IS NOT A ``streamable_http_client`` KEYWORD AT ALL --
   neither ``cache=`` nor ``cache_mode=`` (the brief's two guesses) exists on
   that function; passing either raises ``TypeError: unexpected keyword
   argument``. Response caching lives on ``mcp.Client`` itself:
   ``Client(server, *, cache: CacheConfig | None = CacheConfig())`` -- the
   *default* already honours server ``ttlMs``/``cacheScope`` hints with a
   per-client in-memory store, so caching is ON unless told otherwise.
   ``cache=None`` on the ``Client`` (not the transport) is what disables it;
   confirmed empirically (``Client(transport, cache=None).cache is None``).
   Necessary here because ``ListToolsResult`` is a ``CacheableResult`` and a
   cached listing would defeat per-token filtering for whichever caller's
   listing got cached first -- this shim's ``Client`` is shared across every
   call the local agent makes in one process lifetime, not recreated per
   request.

4. THE BROKER'S OWN ``serverInfo`` STAMP LANDS ON *EVERY* 2026-07-28 RESULT,
   NOT JUST ``tools/list``. ``mcp/server/runner.py::_stamp_server_info`` runs
   for every handler result on the modern era, so a forwarded
   ``CallToolResult`` carries the broker's identity in
   ``_meta['io.modelcontextprotocol/serverInfo']`` exactly like a forwarded
   ``ListToolsResult`` does (measured: both keys equal
   ``{"name": "warden", "version": ""}`` against the mounted surface). The
   brief only stripped it in ``on_list_tools``; ``on_call_tool`` strips it
   too, here, or the broker's own identity leaks to the downstream agent on
   every successful tool call. After stripping, the shim's OWN local
   ``Server`` (see ``_build_shim_server``) re-stamps the SAME ``_meta`` key
   with the shim's own identity ("warden-shim") on its way out over stdio --
   measured end to end -- which is the intended outcome: the downstream
   agent sees the shim's identity, never the broker's.

5. ``TokenFileAuth`` DID NOT CHECK OWNERSHIP. The brief's ``read()`` refused
   a group- or world-readable file but never compared ``st_uid`` against the
   invoking uid, so a token file placed by a different (e.g. root-owned,
   misconfigured) process would be read anyway. Added: ``st.st_uid !=
   os.getuid()`` raises before the permission-bits check runs.

CONFIRMED EXACTLY AS THE BRIEF DESCRIBED (nothing to change):

- ``httpx2.Auth``'s subclassing contract: override ``auth_flow(self,
  request) -> Generator[Request, Response, None]``, ``yield request`` to
  dispatch it. ``Auth``'s default ``sync_auth_flow``/``async_auth_flow``
  both defer to it (``httpx2/_auth.py``), and ``async_auth_flow`` does so by
  calling the sync generator directly rather than off-loading it to a
  thread -- matching the brief's own reasoning that a local file read is
  cheap enough not to need one. Measured: each JSON-RPC call opens its own
  POST (``StreamableHTTPTransport.post_writer`` spawns one
  ``_handle_post_request`` per outgoing ``JSONRPCRequest``), so
  ``auth_flow`` really does run once per forwarded call, not once per
  session -- verified end to end by rewriting the token file between two
  forwarded calls and observing the broker's audit log record two different
  outcomes for the two different tokens.
- ``mcp.server.stdio.stdio_server()`` and the low-level
  ``Server(..., on_list_tools=, on_call_tool=)`` shape (Task 11 confirmed
  this for the broker side; identical here). Worth noting for THIS module:
  ``stdio_server()`` claims fd 0/1 for the duration (fd 0 -> the null
  device, fd 1 -> stderr) and restores them on exit, so anything a handler
  or a child process accidentally prints while the shim is serving lands on
  stderr, never on the wire -- a second, SDK-level backstop behind "never
  write the token to stdout or stderr" below.
- ``mode="auto"`` (the ``Client`` default) DOES negotiate the broker's
  modern-only era on its own: it probes ``server/discover`` at
  ``2026-07-28`` first and only falls back to the legacy handshake on
  negative evidence. Measured against a real mounted surface (era-gated
  exactly like production): the session's negotiated
  ``protocol_version`` came back ``"2026-07-28"``, and the probe carries the
  header exactly once. No pinning needed; ``mode`` is left at its default.

THE SIX HARDENING RULES THIS MODULE ENFORCES, EACH WITH A TEST in
tests/warden/test_mcp_shim.py:

1. ``trust_env=False`` on the upstream client (``build_upstream_client``).
2. The token is read fresh from disk on every request, never captured once
   (``TokenFileAuth.auth_flow``, an ``httpx2.Auth`` subclass rather than a
   fixed header).
3. No redirects (``follow_redirects=False``) -- a 3xx would relocate the
   ``Authorization`` header to whatever origin the response named.
4. ``https`` required, with an explicit ``--allow-http`` for loopback
   development (``validate_broker``).
5. Response caching disabled at the ``Client`` (see deviation 3 above).
6. The broker's ``serverInfo`` is stripped from every forwarded result
   (``_strip_server_info``, applied in both handlers); the token is never
   written to stdout or stderr; a token file that is group- or
   world-readable, or not owned by the invoking uid, is refused rather than
   read.

Plus: the shim never exits on a 401 and never tears down its upstream
client. This is not special-cased here -- it falls out of
``Server.run()``'s own default (``raise_exceptions=False``): "exceptions are
returned as messages to the client" rather than propagating out of the
serve loop. Measured end to end: forwarding a call on a since-invalidated
token raises inside ``on_call_tool``, the downstream agent sees one failed
call, and the SAME upstream ``Client`` (and therefore the SAME
``TokenFileAuth``, watching the SAME path) serves the very next call
successfully once the token file is fixed -- no restart, no reconnect.

(`from mcp import ...` below reaches the installed SDK, not this module.
Python 3 has no implicit relative imports, so a module named `mcp_shim`
inside `warden.cli` cannot shadow the top-level `mcp` package for its own
imports -- and the `mcp` extra is optional, so every SDK import is deferred
into function bodies rather than sitting at module scope, matching how
warden/broker/mcp.py handles the same optional dependency. `httpx2` is part
of that deferral too, even though it is `mcp`'s own transitive dependency
rather than something this module talks to the SDK through directly:
`warden.cli.main`'s `_cmd_mcp` imports `run_shim` from this module OUTSIDE
any try/except, so a module-scope `import httpx2` here would turn a missing
extra into an uncaught `ModuleNotFoundError` traceback instead of the clean
`error: install warden[mcp]` every other missing-extra path produces. The one
wrinkle is `TokenFileAuth`, which subclasses `httpx2.Auth` -- a base class
has to exist at class-definition time, so it cannot simply live inside a
`def` the way a function-body `import httpx2` can. `_token_file_auth_class()`
below builds it lazily instead, on first call, and caches the result: every
caller after the first gets back the same class object with no repeated
import or repeated class construction, and nothing at module scope ever
touches `httpx2` at all.)
"""

from __future__ import annotations

import functools
import os
import stat
from pathlib import Path
from urllib.parse import urlparse

# The wire key the SDK stamps onto every 2026-07-28 result's `_meta`
# (mcp_types._types.SERVER_INFO_META_KEY). Named once, not re-spelled at each
# call site, so the two strip points in this module can never drift apart.
_SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"


@functools.lru_cache(maxsize=1)
def _token_file_auth_class():
    """Builds and caches the `TokenFileAuth` class, importing `httpx2` only
    on first call rather than at module scope -- see the module docstring's
    closing paragraph for why that matters. `lru_cache` rather than a
    module-level `_cls = None` sentinel: it is the same one-time-then-cached
    shape without a mutable global to get out of sync, and every call site
    below reads as "the class", not "build it, unless already built".

    Reads the task token from disk on every request, never once. A `Client`
    captures its `httpx2.AsyncClient`'s default headers at construction time;
    a bare `Authorization` header set once would never see a token rewritten
    later, which only breaks once renewal exists, as "the session dies at the
    first refresh". Subclassing `httpx2.Auth` instead means the read happens
    inside `auth_flow`, which the client calls fresh before every outgoing
    request.
    """
    import httpx2

    class TokenFileAuth(httpx2.Auth):
        def __init__(self, path: Path) -> None:
            self._path = Path(path)

        def read(self) -> str:
            st = self._path.stat()
            if st.st_uid != os.getuid():
                raise PermissionError(
                    f"{self._path} is not owned by this process's uid "
                    f"({os.getuid()}); refusing to read it"
                )
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise PermissionError(
                    f"{self._path} is group- or world-accessible; it must be 0600"
                )
            return self._path.read_text(encoding="utf-8").strip()

        def auth_flow(self, request):
            request.headers["Authorization"] = f"Bearer {self.read()}"
            yield request

    return TokenFileAuth


def validate_broker(url: str, *, allow_http: bool = False) -> str:
    """Refuses a plain-http broker URL unless the caller opted in.

    An http:// broker means the task token rides the wire in the clear on
    every forwarded call, indefinitely -- acceptable only for loopback
    development, and only when asked for by name.
    """
    scheme = urlparse(url).scheme
    if scheme == "https":
        return url
    if scheme == "http" and allow_http:
        return url
    raise ValueError(
        f"--broker must be https (got {scheme!r}); pass --allow-http for "
        f"loopback development"
    )


def build_upstream_client(broker: str) -> httpx2.AsyncClient:
    """The httpx2 client the upstream MCP transport sends every request
    through. Every keyword here is one of the six hardening rules."""
    import httpx2

    return httpx2.AsyncClient(
        base_url=broker,
        # The agent that launched this process is told (rung 0) to export
        # HTTP_PROXY/HTTPS_PROXY pointed at warden's own egress proxy.
        # Honouring them here would send this client's POST to that proxy in
        # absolute form, where a non-CONNECT method is refused and audited --
        # so the shim would never reach the broker, and would fill the audit
        # log with egress probes on the way.
        trust_env=False,
        # A 3xx would move the Authorization header to whatever origin the
        # response named -- httpx2 never re-sends it to a different origin
        # on a followed redirect, but the simplest guarantee is to never
        # follow one at all.
        follow_redirects=False,
        timeout=60.0,
    )


def _strip_server_info(result):
    """The upstream's own identity travels in a 2026-07-28 result's `_meta`
    (every result, not only a listing -- see the module docstring's fourth
    deviation). It is the broker's identity, not this shim's, and nothing
    downstream needs it. Mutates and returns `result` so both call sites can
    stay one line."""
    meta = getattr(result, "meta", None)
    if isinstance(meta, dict):
        meta.pop(_SERVER_INFO_META_KEY, None)
    return result


def _connect_upstream(transport):
    """The `mcp.Client` wrapping `transport`, response caching OFF.

    Extracted from `run_shim` so the caching ban is a testable, one-line
    contract: `ListToolsResult` is a `CacheableResult`, and this shim's
    `Client` is long-lived across every call the local agent makes, so a
    cached listing from one moment would silently outlive whatever the
    token was scoped to when it was fetched. `cache=None` on `Client` --
    NOT on `streamable_http_client`, which has no cache keyword at all --
    is what turns that off; see the module docstring's third deviation.
    """
    from mcp import Client

    return Client(transport, cache=None)


def _build_shim_server(upstream):
    """The local MCP `Server` that speaks to the downstream agent, wired to
    forward both verbs to `upstream` and strip the broker's identity off
    the way back. A plain function (not a class) because the two closures
    are the entire behaviour and `Server`'s constructor is the only thing
    that needs to see them.
    """
    from mcp.server import Server

    async def on_list_tools(ctx, params):
        return _strip_server_info(await upstream.list_tools())

    async def on_call_tool(ctx, params):
        # `arguments: null` (a tool with no arguments) reads as {}, matching
        # how the HTTP and MCP surfaces on the broker side already normalise
        # a missing/null argument object -- this shim raises neither
        # question, it only forwards the one the broker will ask again.
        return _strip_server_info(
            await upstream.call_tool(params.name, params.arguments or {})
        )

    return Server(
        "warden-shim", on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )


def run_shim(broker: str, token_file: Path, *, allow_http: bool = False) -> int:
    """Serve MCP over stdio, forwarding every call to `broker`.

    Runs until stdin closes. Never exits on a 401 (see the module
    docstring's closing paragraph) and never rebuilds the upstream `Client`
    -- a token file rewritten mid-session is picked up on the very next
    forwarded call, with no reconnect.
    """
    import anyio
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.stdio import stdio_server

    validate_broker(broker, allow_http=allow_http)
    auth = _token_file_auth_class()(Path(token_file))

    async def main() -> None:
        client = build_upstream_client(broker)
        client.auth = auth
        async with client:
            transport = streamable_http_client(broker, http_client=client)
            async with _connect_upstream(transport) as upstream:
                server = _build_shim_server(upstream)
                async with stdio_server() as (read, write):
                    await server.run(
                        read, write, server.create_initialization_options()
                    )

    anyio.run(main)
    return 0
