"""The shim runs inside an untrusted agent's process tree. It holds one
token, and every rule here exists because something else would take it.

Two layers of test live here. The first is unit-level, against the shim's
own small pieces in isolation (`TokenFileAuth`, `build_upstream_client`,
`validate_broker`, and the private helpers `_strip_server_info`,
`_connect_upstream`, `_build_shim_server`). The second drives the shim's
OWN production code end to end against a real mounted broker app, over
`httpx2.ASGITransport` rather than a socket -- the same technique
tests/warden/test_mcp_surface.py uses for its own client (see
`open_session` there). `_shim_session` below wires exactly what `run_shim`
wires -- `TokenFileAuth`, `build_upstream_client`'s settings,
`_connect_upstream`, `_build_shim_server` -- and then opens a SECOND,
downstream `mcp.Client` against the resulting shim `Server` in-process:
that second client is what a real stdio-connected agent's own MCP client
is, one hop further out. The only thing it does not exercise is the literal
`stdio_server()` call in `run_shim`, which needs real file descriptors an
in-process test cannot supply -- see the module's closing comment for what
that gap does and does not cover.
"""

from __future__ import annotations

import contextlib
import os

import pytest

pytest.importorskip("mcp", reason="requires the warden[mcp] extra")

from warden.cli.mcp_shim import (
    _token_file_auth_class,
    build_upstream_client,
    validate_broker,
)

# `TokenFileAuth` itself is not a module-level name: it subclasses
# `httpx2.Auth`, and the module builds it lazily inside
# `_token_file_auth_class()` so that importing `warden.cli.mcp_shim` never
# needs `httpx2` -- see that module's docstring. `TokenFileAuth` below is
# this test module's own bound name for the (cached, so this is one class
# for the whole run) class the factory returns.
TokenFileAuth = _token_file_auth_class()


# --- Unit level: the six hardening rules, in isolation ----------------------


def test_the_upstream_client_ignores_proxy_environment(monkeypatch):
    """The shim is a child of the agent, and rung 0 tells operators to export
    HTTP_PROXY pointed at warden's own egress proxy. Inheriting it sends the
    shim's POST to :3128 in absolute form, where the proxy 405s every
    non-CONNECT method -- so the shim never reaches the broker at all, and
    every attempt is audited as an egress probe."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    client = build_upstream_client("https://broker.internal")
    assert client.trust_env is False


def test_redirects_are_not_followed():
    """A 3xx relocates the Authorization header to another origin, and under
    renewal that token is refreshed on a timer -- a durable capability rather
    than a five-minute leak."""
    client = build_upstream_client("https://broker.internal")
    assert client.follow_redirects is False


def test_plain_http_is_refused_without_an_explicit_opt_in():
    with pytest.raises(ValueError, match="https"):
        validate_broker("http://broker.internal", allow_http=False)
    assert validate_broker("http://127.0.0.1:8080", allow_http=True)
    assert validate_broker("https://broker.internal", allow_http=False)


def test_the_token_is_read_per_request_not_captured_once(tmp_path):
    """A Client captures headers at construction, so a token file that is
    rewritten later would never be picked up -- and that only breaks once
    renewal exists, as 'the session dies at the first refresh'."""
    token_file = tmp_path / "token"
    token_file.write_text("first")
    # 0600: this test's subject is the per-request re-read, not the
    # permission check -- `Path.write_text` on a fresh file honours the
    # process umask (0644 under the common 022), which the permission check
    # below would legitimately refuse before ever reaching the behaviour
    # this test exists to prove. `write_text` truncates in place on the
    # second call below rather than recreating the file, so one chmod here
    # covers both reads.
    token_file.chmod(0o600)
    auth = TokenFileAuth(token_file)

    class Req:
        def __init__(self):
            self.headers = {}

    a = Req()
    next(auth.auth_flow(a))
    assert a.headers["Authorization"] == "Bearer first"

    token_file.write_text("second")
    b = Req()
    next(auth.auth_flow(b))
    assert b.headers["Authorization"] == "Bearer second"


def test_a_world_readable_token_file_is_refused(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("t")
    token_file.chmod(0o644)
    with pytest.raises(PermissionError, match="0600"):
        TokenFileAuth(token_file).read()


def test_a_token_file_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    """Ownership, not just permission bits: a 0600 file placed by a
    different uid (a misconfigured launcher, a container image that ships a
    stray credential) is refused too, even though its mode alone would pass.
    No real second uid is available in a test sandbox, so the invoking uid
    is the one faked instead -- from the file's point of view that is
    exactly the same fact: "the reader is not the owner"."""
    from warden.cli import mcp_shim

    token_file = tmp_path / "token"
    token_file.write_text("t")
    token_file.chmod(0o600)

    real_uid = os.getuid()
    monkeypatch.setattr(mcp_shim.os, "getuid", lambda: real_uid + 1)
    with pytest.raises(PermissionError, match="uid"):
        TokenFileAuth(token_file).read()


def test_the_token_never_reaches_stdout_or_stderr(tmp_path, capsys):
    token_file = tmp_path / "token"
    token_file.write_text("do-not-print-me")
    token_file.chmod(0o600)

    class Req:
        def __init__(self):
            self.headers = {}

    next(TokenFileAuth(token_file).auth_flow(Req()))

    captured = capsys.readouterr()
    assert "do-not-print-me" not in captured.out
    assert "do-not-print-me" not in captured.err


def test_response_caching_is_disabled():
    """ListToolsResult is a CacheableResult, and this shim's Client is
    shared across every call the local agent makes for the life of the
    process -- a cached listing would silently outlive whatever the token
    was scoped to when it was fetched. `cache=None` has to land on
    `mcp.Client`, not on `streamable_http_client`, which has no cache
    keyword at all (see the module docstring's third deviation);
    `_connect_upstream` is where that lands, and this is its one-line
    contract."""
    from warden.cli.mcp_shim import _connect_upstream

    upstream = _connect_upstream(object())
    assert upstream.cache is None


def test_server_info_metadata_is_stripped_from_a_forwarded_result():
    from warden.cli.mcp_shim import _strip_server_info

    class FakeResult:
        def __init__(self, meta):
            self.meta = meta

    stripped = _strip_server_info(
        FakeResult(
            {"io.modelcontextprotocol/serverInfo": {"name": "warden"}, "other": 1}
        )
    )
    assert stripped.meta == {"other": 1}

    # No _meta at all (a handshake-era result, or nothing to strip): untouched.
    untouched = _strip_server_info(FakeResult(None))
    assert untouched.meta is None


# --- End to end: the shim's own code, against a mounted broker -------------


def _run(client, go):
    """Runs `go()` on the app's lifespan loop and unwraps anyio's exception
    groups on the way out -- the same technique
    tests/warden/test_mcp_surface.py's `run_on_the_apps_loop` uses, needed
    here too since a protocol error raised deep inside the upstream
    Client's own task group can arrive wrapped."""
    try:
        return client.portal.call(go)
    except BaseExceptionGroup as group:
        leaf: BaseException = group
        while isinstance(leaf, BaseExceptionGroup) and len(leaf.exceptions) == 1:
            leaf = leaf.exceptions[0]
        raise leaf from None


@contextlib.asynccontextmanager
async def _shim_session(client, token_file):
    """Wires the shim's own production code -- TokenFileAuth,
    build_upstream_client's settings, `_connect_upstream`,
    `_build_shim_server` -- to the mounted broker app via ASGITransport,
    then opens a second, downstream `mcp.Client` against the resulting shim
    `Server` in-process. Everything between the two `Client()` calls below
    is exactly what `run_shim` builds, short of the literal
    `stdio_server()` call, which needs real file descriptors this
    in-process test cannot supply.

    `build_upstream_client` itself is not called here: it always builds a
    real-network httpx2 transport with no way to substitute
    `ASGITransport`, so this constructs the client by hand instead --
    matching `build_upstream_client`'s own trust_env/follow_redirects
    settings rather than reusing its code, exactly as
    test_mcp_surface.py's own `open_session` does for the broker's client.
    """
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    from warden.cli.mcp_shim import _build_shim_server, _connect_upstream

    http = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=client.app),
        base_url="http://testserver",
        trust_env=False,
        follow_redirects=False,
    )
    http.auth = TokenFileAuth(token_file)
    async with http:
        transport = streamable_http_client("http://testserver/mcp", http_client=http)
        async with _connect_upstream(transport) as upstream:
            shim_server = _build_shim_server(upstream)
            async with Client(shim_server) as downstream:
                yield downstream, upstream


def test_the_shim_forwards_a_call_end_to_end_and_negotiates_the_modern_era(tmp_path):
    """The whole bet, proven against the shim's own code rather than a
    stub: a real tool call reaches the broker, is decided by its spine, and
    the connection negotiates the SAME modern era the broker's era gate
    requires (mode='auto' is the Client default; no pinning needed -- see
    the module docstring)."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token_file = tmp_path / "token"
    token_file.write_text(token_for(signer))
    token_file.chmod(0o600)

    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):

        async def go():
            async with _shim_session(client, token_file) as (downstream, upstream):
                result = await downstream.call_tool("read_document", {"doc_id": "a"})
                return result, upstream.session.protocol_version

        result, negotiated = _run(client, go)

    assert result.is_error is False
    assert negotiated == "2026-07-28"
    assert [r["decision"] for r in audit.records()] == ["allow"]


def test_the_brokers_identity_is_stripped_from_both_listings_and_calls(tmp_path):
    """Rule 6's meta-stripping, proven at both call sites the broker's
    identity can travel through. The SDK stamps `_meta` on EVERY
    2026-07-28 result, not only a listing (the module docstring's fourth
    deviation from the brief, which only stripped `on_list_tools`) -- so a
    forwarded tool call carries the broker's identity exactly like a
    forwarded listing does unless both handlers strip it. Once stripped,
    the shim's OWN local Server re-stamps its own identity in the same
    slot -- that is the SDK doing it automatically, not this shim, and it
    is what proves the broker's name is really gone rather than merely
    absent."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token_file = tmp_path / "token"
    token_file.write_text(token_for(signer))
    token_file.chmod(0o600)

    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        _audit,
    ):

        async def go():
            async with _shim_session(client, token_file) as (downstream, _upstream):
                listing = await downstream.list_tools()
                result = await downstream.call_tool("read_document", {"doc_id": "a"})
                return listing, result

        listing, result = _run(client, go)

    for meta in (listing.meta, result.meta):
        assert meta is not None
        info = meta["io.modelcontextprotocol/serverInfo"]
        assert info["name"] == "warden-shim"
        assert info["name"] != "warden"


def test_the_broker_observes_two_different_tokens_across_two_forwarded_calls(
    tmp_path,
):
    """Rule 2, proven at full stack rather than against a stub Auth: the
    token file is rewritten between two calls on the SAME shim session --
    same upstream Client, same TokenFileAuth instance, same open
    connection -- and the broker's own audit log shows it decided against
    two different tokens, not the first one twice."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token_file = tmp_path / "token"
    token_file.write_text(token_for(signer, task_id="one"))
    token_file.chmod(0o600)

    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):

        async def go():
            async with _shim_session(client, token_file) as (downstream, _upstream):
                first = await downstream.call_tool("read_document", {"doc_id": "a"})
                token_file.write_text(token_for(signer, task_id="two"))
                second = await downstream.call_tool("read_document", {"doc_id": "a"})
                return first, second

        first, second = _run(client, go)

    assert first.is_error is False
    assert second.is_error is False
    assert [r["task_id"] for r in audit.records()] == ["one", "two"]


def test_a_401_does_not_tear_down_the_shim_or_its_upstream(tmp_path):
    """The shim must never exit on a 401 and never rebuild its upstream
    Client -- otherwise a token file rewritten mid-session (renewal) is
    never picked up, because nothing is left watching it. Proven by
    breaking the token, observing the failure, fixing the token, and then
    reusing the exact SAME downstream session, shim Server, and upstream
    Client for one more call."""
    from mcp.shared.exceptions import MCPError

    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    token_file = tmp_path / "token"
    token_file.write_text(token)
    token_file.chmod(0o600)

    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):

        async def go():
            async with _shim_session(client, token_file) as (downstream, _upstream):
                good = await downstream.call_tool("read_document", {"doc_id": "a"})

                token_file.write_text("not-a-real-token")
                raised = None
                try:
                    await downstream.call_tool("read_document", {"doc_id": "a"})
                except MCPError as exc:
                    raised = exc

                token_file.write_text(token)
                recovered = await downstream.call_tool("read_document", {"doc_id": "a"})
                return good, raised, recovered

        good, raised, recovered = _run(client, go)

    assert good.is_error is False
    assert raised is not None
    assert "Unauthenticated" in raised.message
    assert recovered.is_error is False
    assert [r["decision"] for r in audit.records()] == ["allow", "deny", "allow"]


# --- The extra genuinely absent, driven through the CLI ---------------------
#
# Everything above runs with `mcp` (and therefore `mcp_types` and `httpx2`)
# actually installed -- this test file's own `importorskip` at the top
# requires it. The two tests below simulate the OTHER case -- an operator
# who ran `pip install warden` without the `[mcp]` extra -- from inside that
# same installed environment, by poisoning `sys.modules` rather than by
# actually uninstalling anything.


def _poison_mcp_extra(monkeypatch):
    """Makes `mcp`, `mcp_types`, and `httpx2` unimportable for the rest of
    this test -- the same `sys.modules[name] = None` technique
    test_mcp_surface.py's own `test_enabling_the_surface_without_the_extra_
    fails_at_boot` uses for `mcp` alone.

    Evicting every already-cached submodule under these three roots first is
    what makes it work HERE: a bare `sys.modules["mcp"] = None` does not
    stop `from mcp.client.streamable_http import ...` once that submodule is
    already fully imported and cached under its own dotted name -- as it
    always is by the time this test runs, from the real-SDK tests earlier in
    this same file. Measured: without the eviction loop below, `run_shim`
    reaches its upstream connection instead of raising. Deleting every
    cached entry first forces the next import of any of them to re-resolve
    starting from the (poisoned) top-level name, exactly as it would in a
    process where the package was never installed at all.

    `warden.cli.mcp_shim` and `warden.cli.main` are evicted too, and for the
    identical reason: this test file's own top-of-module `from
    warden.cli.mcp_shim import ...` already fully imported and cached the
    REAL mcp_shim -- with a real, working module-scope `import httpx2` if
    one ever crept back in -- long before this test runs. Without evicting
    it here, that module-scope statement (the exact bug this fix removes)
    would never re-run under the poisoned environment, and a regression that
    reintroduced it would pass this test by accident, for the same reason a
    stale cache always hides an import-time regression: the broken line
    simply never executes a second time.
    """
    import sys

    roots = ("mcp", "mcp_types", "httpx2")
    prefixes = tuple(f"{root}." for root in roots)
    for name in list(sys.modules):
        if name in roots or name.startswith(prefixes):
            monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.delitem(sys.modules, "warden.cli.mcp_shim", raising=False)
    monkeypatch.delitem(sys.modules, "warden.cli.main", raising=False)
    for root in roots:
        monkeypatch.setitem(sys.modules, root, None)


def test_mcp_help_works_without_the_extra_installed(monkeypatch, capsys):
    """`warden mcp --help` must work whether or not `warden[mcp]` is
    installed, because argparse builds and prints the subcommand's help --
    and exits -- before `_cmd_mcp`, and therefore this module, is ever
    reached. Proven with mcp, mcp_types AND httpx2 all made unimportable."""
    from warden.cli.main import main as cli_main

    _poison_mcp_extra(monkeypatch)

    with pytest.raises(SystemExit) as exc_info:
        cli_main(["mcp", "--help"])
    assert exc_info.value.code == 0

    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "--broker" in captured.out


def test_cmd_mcp_reports_a_missing_extra_cleanly_not_a_traceback(monkeypatch, capsys):
    """The gap this fix closes. `_cmd_mcp`'s `from warden.cli.mcp_shim import
    run_shim` used to raise `ModuleNotFoundError: No module named 'httpx2'`
    itself -- outside any try/except -- because mcp_shim.py imported httpx2
    at module scope (see that module's docstring). Deferring the import
    fixes THAT path: this module no longer needs `httpx2` (or `mcp`, or
    `mcp_types`) to be importable at all. But `run_shim`'s own body still
    imports `mcp` the moment it actually runs, inside `_cmd_mcp`'s
    try/except -- so `_cmd_mcp` now also catches `ImportError` there, and
    this proves the result is the same clean `error: ...` line every other
    missing-extra path in this codebase gives, not a bare traceback. Driven
    with all three names poisoned: any one of them missing is the identical
    "extra not installed" fact from an operator's point of view."""
    from warden.cli.main import main as cli_main

    _poison_mcp_extra(monkeypatch)

    exit_code = cli_main(
        [
            "mcp",
            "--broker",
            "https://broker.internal/mcp",
            "--token-file",
            "/nonexistent-token-file",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert captured.err.strip().startswith("error:")
    assert "warden[mcp]" in captured.err
