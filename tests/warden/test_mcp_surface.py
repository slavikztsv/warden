"""The MCP surface: mounted, authenticated, and off unless asked for.

**How the surface is driven here.** In-process, with the SDK's own client, over
`httpx2.ASGITransport` pointed at the app -- no uvicorn, no loopback port, no
thread fixture. `streamable_http_client(url, http_client=...)` does accept a
pre-built `httpx2.AsyncClient` in 2.0.0, which is what makes that possible; the
brief's fallback (a real port under uvicorn) was not needed.

The one subtlety is which event loop things run on. A streamable-HTTP request
is served inside the session manager's task group, and that task group is
created by the manager's `run()` -- which the app's lifespan enters. So the
client coroutines have to run on the same loop as the lifespan, or the request
arrives in one loop and the task group meant to serve it lives in another.
`TestClient.__enter__` runs the lifespan on a blocking portal and leaves it on
`.portal`, so every call below is submitted through that. A plain
`anyio.run(...)` here would be a second loop.
"""

from __future__ import annotations

import contextlib
import threading

import pytest

mcp = pytest.importorskip("mcp", reason="requires the warden[mcp] extra")

# Only reachable once "mcp" itself imported cleanly -- importorskip above
# aborts the whole module before this line runs otherwise, and mcp_types is
# one of mcp==2.0.0's own pinned dependencies, so it is never absent when
# "mcp" is present.
from mcp_types.version import (  # noqa: E402
    HANDSHAKE_PROTOCOL_VERSIONS,
    MODERN_PROTOCOL_VERSIONS,
)

UNSUPPORTED_PROTOCOL_VERSION = -32022


def test_telemetry_is_a_no_op_after_the_broker_boots(monkeypatch):
    """The happy path: nothing has claimed the process-global TracerProvider
    yet, so _silence_telemetry() both installs the no-op and sees it stick.

    OTel's global provider is a process-wide set-once (the first caller in
    the PROCESS wins, not the first caller in this test), and dozens of
    other tests in this suite call build() -- and therefore
    _silence_telemetry() -- earlier in collection order. Left alone, this
    test would pass regardless of whether THIS call succeeded, because an
    earlier call already won the Once and installed the same provider type.
    Resetting OTel's globals first makes the outcome depend on this call.
    """
    from opentelemetry import trace
    from opentelemetry.trace import NoOpTracerProvider
    from opentelemetry.util._once import Once

    from warden.broker.__main__ import _silence_telemetry

    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", Once())

    _silence_telemetry()

    assert type(trace.get_tracer_provider()) is NoOpTracerProvider


def test_silence_telemetry_refuses_to_start_if_a_provider_got_there_first(monkeypatch):
    """The defeat path: something else -- opentelemetry-instrument, a
    Kubernetes OTel Operator webhook, a site-wide sitecustomize.py -- won
    the process-global set-once before the broker's own code ran.
    set_tracer_provider() then silently no-ops (it logs a warning and
    raises nothing), so _silence_telemetry() must check the outcome itself
    and refuse to start rather than let the broker boot believing telemetry
    is silenced while a live exporter stays installed.
    """
    from opentelemetry import trace
    from opentelemetry.util._once import Once

    from warden.broker.__main__ import _silence_telemetry
    from warden.broker.config.loader import ConfigError

    class FakeRealProvider(trace.TracerProvider):
        def get_tracer(self, *args, **kwargs):
            return trace.NoOpTracer()

    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", Once())
    trace.set_tracer_provider(FakeRealProvider())

    with pytest.raises(ConfigError):
        _silence_telemetry()


def test_silence_telemetry_still_passes_on_a_repeated_call_in_the_same_process():
    """The suite calls build() -- and therefore _silence_telemetry() --
    many times in one process. After the first call wins the Once and
    installs the no-op, every later call must still see a no-op provider
    and PASS, even though its own set_tracer_provider() call is a no-op
    that logs "Overriding of current TracerProvider is not allowed". The
    check has to be "is the current provider a no-op", not "did MY call
    win the Once" -- the latter would fail every test after the first.

    Deliberately does not reset OTel's globals first. That makes this test
    order-independent rather than order-dependent: whatever the first call
    below finds -- untouched state (it wins the Once itself) or a
    NoOpTracerProvider some earlier test's build() already installed (it
    loses the Once, silently) -- the outcome check must find a no-op
    provider either way, or this whole suite already failed earlier. The
    second call is then guaranteed to be the repeated, Once-losing case
    that production's many build() calls hit, and must still pass.
    """
    from opentelemetry import trace
    from opentelemetry.trace import NoOpTracerProvider

    from warden.broker.__main__ import _silence_telemetry

    _silence_telemetry()
    _silence_telemetry()

    assert type(trace.get_tracer_provider()) is NoOpTracerProvider


# --- Driving the mounted surface -------------------------------------------


@contextlib.asynccontextmanager
async def open_session(client, token):
    """An SDK client session against the app the TestClient wraps.

    The credential rides the httpx client's default headers rather than a
    `headers=` argument to `streamable_http_client`, which has none: in 2.0.0
    that factory takes only `url`, `http_client` and `terminate_on_close`, and
    its docstring says to configure headers on the client you hand it.
    """
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=client.app),
        base_url="http://testserver",
        headers=headers,
        trust_env=False,
    ) as http:
        async with Client(
            streamable_http_client("http://testserver/mcp", http_client=http)
        ) as session:
            yield session


def run_on_the_apps_loop(client, go):
    """Runs `go()` on the loop the app's lifespan is running on, and unwraps
    anyio's exception groups on the way out.

    A protocol error the surface sends comes back as a JSON-RPC error and is
    re-raised client-side inside the transport's task group -- which wraps
    anything escaping it in an ExceptionGroup, once per nested group. Tests
    assert on the error the surface actually sent, so the wrappers come off
    here instead of in each test.
    """
    try:
        return client.portal.call(go)
    except BaseExceptionGroup as group:
        leaf: BaseException = group
        while isinstance(leaf, BaseExceptionGroup) and len(leaf.exceptions) == 1:
            leaf = leaf.exceptions[0]
        raise leaf from None


def call_tool(client, token, name, arguments):
    async def go():
        async with open_session(client, token) as session:
            return await session.call_tool(name, arguments)

    return run_on_the_apps_loop(client, go)


def list_tools(client, token):
    async def go():
        async with open_session(client, token) as session:
            return await session.list_tools()

    return run_on_the_apps_loop(client, go)


# --- The surface -----------------------------------------------------------


def test_the_surface_is_absent_unless_enabled(tmp_path):
    from tests.warden.test_app import build

    from warden.broker.identity import Signer

    signer = Signer.generate()
    client, _ = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    assert not any(getattr(r, "path", "").startswith("/mcp") for r in client.app.routes)
    assert client.post("/mcp").status_code == 404


def test_a_call_is_decided_by_the_same_spine(tmp_path):
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        result = call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})
        assert result.is_error is False
        assert "doc-body" in result.content[0].text
        assert [r["decision"] for r in audit.records()] == ["allow"]


def test_a_denial_is_a_tool_error_naming_the_rule(tmp_path):
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(
        tmp_path, signer, {"allow": False, "deny_reasons": ["rows.bounded"]}
    ) as (client, audit):
        result = call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})
        assert result.is_error is True
        assert "rows.bounded" in result.content[0].text
        assert [r["decision"] for r in audit.records()] == ["deny"]


def test_both_front_doors_decide_one_call_the_same_way(tmp_path):
    """The whole reason this surface exists in the same process.

    One app, one spine: a call over HTTP and the same call over MCP produce
    the same decision and land in the same audit chain, in order. Two
    processes could not assert this, and two spines would not hold it.
    """
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    with build_with_mcp(
        tmp_path, signer, {"allow": False, "deny_reasons": ["rows.bounded"]}
    ) as (client, audit):
        http = invoke(client, token, "read_document", {"doc_id": "a"})
        over_mcp = call_tool(client, token, "read_document", {"doc_id": "a"})

    assert http.status_code == 403
    assert http.json()["rule"] == "rows.bounded"
    assert over_mcp.is_error is True
    assert "rows.bounded" in over_mcp.content[0].text
    records = audit.records()
    assert [r["rule"] for r in records] == ["rows.bounded", "rows.bounded"]
    assert [r["seq"] for r in records] == [1, 2]


def test_an_unauthenticated_call_is_a_protocol_error_recorded_once(tmp_path):
    """No credential is not something a model can adapt to, so it is a
    protocol error rather than a tool error -- and it leaves exactly ONE
    record, the same as the HTTP surface's refusal.

    The count is the load-bearing half. On the 2026-07-28 path the SDK runs
    this server's own tools/list handler inline, before dispatching a
    tools/call, to fetch the called tool's schema; left alone that asks the
    spine twice and writes the sentinel refusal twice for one probe.
    """
    from mcp.shared.exceptions import MCPError

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        with pytest.raises(MCPError) as caught:
            call_tool(client, None, "read_document", {"doc_id": "a"})

    assert "Unauthenticated" in caught.value.message
    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "deny"
    assert records[0]["rule"] == "unauthenticated"


def test_an_authenticated_call_is_decided_once_not_twice(tmp_path):
    """The same inline-listing hazard, on the path that succeeds: one
    tools/call must reach the spine once, however many times the SDK consults
    the tool catalog on its way there.

    `list_tools` is the load-bearing half of this and used to be missing. The
    inline lookup calls list_tools, NOT handle_tool_call, so a version of this
    test that spied only the latter passed with the guard deleted.

    The counts are measured, both ways. Guard on: handle_tool_call 1,
    list_tools 1 -- that one listing is the SDK client's own `tools/list`,
    which it issues before calling. Guard replaced by `lambda ctx: False`:
    handle_tool_call 1, list_tools 2. So the number below is what fails if the
    guard ever stops firing.
    """
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    decided, listed = [], []
    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        spine = client.app.state.spine
        decide, listing = spine.handle_tool_call, spine.list_tools
        spine.handle_tool_call = lambda *a: (decided.append(a), decide(*a))[1]
        spine.list_tools = lambda *a: (listed.append(a), listing(*a))[1]
        result = call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})

    assert result.is_error is False
    assert len(decided) == 1
    assert len(listed) == 1, "the SDK's inline schema lookup must not reach the spine"
    assert [r["decision"] for r in audit.records()] == ["allow"]


def test_the_spine_runs_on_the_event_loop_not_a_worker_thread(tmp_path):
    """The handler is `async def` and calls the spine inline, so the taint
    snapshot and the read it authorises happen on one thread with no
    scheduling boundary between them. A sync handler would be dispatched to a
    worker thread and put them on two."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    threads = []
    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        loop_thread = client.portal.call(threading.get_ident)
        spine = client.app.state.spine
        real = spine.handle_tool_call
        spine.handle_tool_call = lambda *a: (
            threads.append(threading.get_ident()),
            real(*a),
        )[1]
        call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})

    assert threads == [loop_thread]


def test_a_null_argument_object_reads_as_no_arguments(tmp_path):
    """`arguments: null` is how a client invokes a tool that takes none, so it
    reaches the spine as {} -- not None, which the spine reserves for a body
    that did not parse and audits as input.malformed. This transport cannot
    produce one of those."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    seen = []
    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        spine = client.app.state.spine
        real = spine.handle_tool_call
        spine.handle_tool_call = lambda *a: (seen.append(a), real(*a))[1]
        call_tool(client, token_for(signer), "read_document", None)

    assert [args for _credential, _tool, args in seen] == [{}]


def test_a_failure_after_the_action_says_not_to_repeat_the_call(tmp_path):
    """The action already happened and the taint update did not, so a retry
    would pass the same row budget twice. The rendering has to say so, and it
    carries the seq of the allow record that stands as the account of it."""
    import httpx

    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(
        tmp_path,
        signer,
        {"allow": True, "deny_reasons": []},
        backend_handler=lambda request: httpx.Response(500, text="upstream on fire"),
    ) as (client, audit):
        result = call_tool(
            client, token_for(signer), "http_fetch", {"url": "http://x.internal/a"}
        )

    assert result.is_error is True
    text = result.content[0].text
    assert "Do not repeat this call." in text
    # The one durable allow record, named so a caller can find what happened.
    records = audit.records()
    assert [r["decision"] for r in records] == ["allow"]
    assert f"(audit record {records[0]['seq']})" in text
    # And nothing of the failure itself.
    assert "upstream on fire" not in text
    assert "x.internal" not in text


def test_an_unrecordable_decision_is_a_protocol_error_naming_no_paths(tmp_path):
    """If it cannot be logged it is not done -- and the caller is told that
    without being told where the log lives."""
    from mcp.shared.exceptions import MCPError

    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        def explode(**kwargs):
            raise OSError("[Errno 28] No space left: /srv/warden/state/audit.jsonl")

        audit.append = explode
        with pytest.raises(MCPError) as caught:
            call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})

    assert "audit.jsonl" not in caught.value.message
    assert "Errno" not in caught.value.message
    assert "record" in caught.value.message


def test_the_listing_is_what_the_token_grants_with_schemas(tmp_path):
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        token = token_for(signer, allowed_tools=["read_document", "send_email"])
        listing = list_tools(client, token)

    assert sorted(tool.name for tool in listing.tools) == ["read_document", "send_email"]
    by_name = {tool.name: tool for tool in listing.tools}
    assert by_name["read_document"].input_schema["properties"]["doc_id"] == {
        "type": "string",
        "minLength": 1,
    }
    # A listing is usability, never enforcement, so it records nothing.
    assert audit.records() == []


def test_an_unauthenticated_listing_is_refused_and_recorded(tmp_path):
    """A listing has no is_error channel, and an empty one would be
    indistinguishable from a token that grants nothing -- so a refusal is a
    protocol error. The catalog is the deployment's map of its own internal
    systems, so the refusal is recorded like any other call without
    authority."""
    from mcp.shared.exceptions import MCPError

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        with pytest.raises(MCPError) as caught:
            list_tools(client, None)

    assert "Unauthenticated" in caught.value.message
    records = audit.records()
    assert [r["action"]["type"] for r in records] == ["tool_list"]
    assert records[0]["rule"] == "unauthenticated"


def test_the_surface_answers_only_under_the_configured_host(tmp_path):
    """McpConfig.host feeds the SDK's DNS-rebinding protection.

    Left unset, `streamable_http_app`'s `host` defaults to 127.0.0.1 and the
    SDK installs a loopback allow-list, which answers 421 to a request
    arriving under any real hostname. Configured, that hostname is what the
    surface accepts. Both halves asserted here, because the claim used to sit
    in McpConfig's docstring with nothing exercising it.

    The modern protocol-version header is required on both calls now that
    `_EraGate` sits in front of the DNS-rebinding check: it reads its own
    header before the request ever reaches `sub`, and a version-less POST
    (what this test sent before that gate existed) is refused with -32022
    before the 421 this test means to exercise is ever reached at all.
    """
    from mcp_types.version import LATEST_MODERN_VERSION

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    headers = {"MCP-Protocol-Version": LATEST_MODERN_VERSION}
    payload = {"allow": True, "deny_reasons": []}

    with build_with_mcp(tmp_path / "unset", signer, payload, host="") as (client, _):
        refused = client.post("/mcp", json=body, headers=headers)
    assert refused.status_code == 421

    with build_with_mcp(tmp_path / "named", signer, payload, host="testserver") as (
        client,
        _,
    ):
        accepted = client.post("/mcp", json=body, headers=headers)
    assert accepted.status_code != 421


# --- Rendering, without a transport ----------------------------------------


def test_no_rendering_repeats_the_exception_text_it_was_handed():
    """Every Outcome whose message is str(exc) is rendered without it.

    Which kinds those are is read off the spine's own groupings rather than
    listed here, so a kind added to any of them is covered the day it exists.
    The DENIED five are deliberately not among them: their message is written
    by the spine itself ("Denied by policy rule ..."), it is the refusal the
    model is meant to read, and this surface passes it through on purpose.

    The two live sources of a str(exc) on the covered paths are the audit
    log's own filesystem errors and the adapters' HTTP client -- an audit path
    and an internal hostname respectively.
    """
    from mcp.shared.exceptions import MCPError

    from warden.broker.mcp import render_call
    from warden.broker.spine import AUDIT_UNAVAILABLE, FAULT, Kind, Outcome

    secret = "host=docs.internal path=/srv/warden/state/audit.jsonl"
    covered = AUDIT_UNAVAILABLE | FAULT | {Kind.UNAUTHENTICATED}
    for kind in covered:
        outcome = Outcome(kind=kind, rule="r", message=secret, audit_seq=7)
        try:
            rendered = render_call(outcome).content[0].text
        except MCPError as exc:
            rendered = f"{exc.message} {exc.data}"
        assert secret not in rendered, kind
        assert "internal" not in rendered, kind
        assert "audit.jsonl" not in rendered, kind


def test_every_kind_has_a_rendering_and_it_is_the_right_channel():
    """Each Kind renders on the channel its meaning requires, and none of them
    escapes as a bare Python exception.

    Split by channel rather than suppressed: an earlier version wrapped the
    assert in `contextlib.suppress(MCPError)`, so a Kind that must be a TOOL
    error (a denial a model can adapt to) would have passed by raising a
    protocol error instead -- the exact confusion this surface exists to
    avoid.
    """
    from mcp.shared.exceptions import MCPError

    from warden.broker.mcp import render_call
    from warden.broker.refusals import AFTER_EXECUTE
    from warden.broker.spine import AUDIT_UNAVAILABLE, DENIED, Kind, Outcome

    tool_errors = DENIED | AFTER_EXECUTE | {Kind.DESCRIBE_BACKEND_FAULT}
    protocol_errors = AUDIT_UNAVAILABLE | {Kind.UNAUTHENTICATED, Kind.LISTED}
    # No Kind is unaccounted for, so a new one added to spine.py fails here
    # rather than quietly landing in whichever branch happens to catch it.
    assert tool_errors | protocol_errors | {Kind.EXECUTED} == set(Kind)

    for kind in tool_errors:
        result = render_call(Outcome(kind=kind, rule="r", message="m", audit_seq=3))
        assert result.is_error is True, kind
        assert result.content[0].text, kind
    for kind in protocol_errors:
        with pytest.raises(MCPError):
            render_call(Outcome(kind=kind, rule="r", message="m", audit_seq=3))


# --- The wiring ------------------------------------------------------------


def test_the_mcp_config_is_not_one_of_the_shared_components():
    """It reaches create_app as its own parameter, never through
    BrokerComponents.

    as_proxy_kwargs() returns as_app_kwargs() verbatim, and serve_proxy's
    authorize_connect is keyword-only with no **kwargs -- so an `mcp` key in
    that dataclass would raise TypeError inside EVERY CONNECT, at request
    time, while the broker still reported healthy.
    """
    import inspect

    from warden.broker.app import create_app
    from warden.broker.wiring import BrokerComponents

    assert "mcp" in inspect.signature(create_app).parameters
    assert "mcp" not in BrokerComponents.__dataclass_fields__
    components = BrokerComponents(
        verifier=None, pdp=None, taint=None, audit=None, policy_digest="d"
    )
    assert "mcp" not in components.as_app_kwargs()
    assert "mcp" not in components.as_proxy_kwargs()


def test_the_broker_process_wires_the_surface_it_was_configured_for(
    tmp_path, monkeypatch
):
    """build() has to hand create_app the config it parsed. Otherwise
    [mcp].enabled is a key the loader reads, validates, and nothing acts on --
    the silent no-op that loader exists to prevent."""
    import dataclasses

    from tests.warden.test_key_split import (
        broker_config,
        set_catalog_env,
        stub_client,
        write_keypair,
    )
    from warden.broker import __main__ as broker_main
    from warden.broker.config.loader import McpConfig

    _, public_path = write_keypair(tmp_path)
    set_catalog_env(monkeypatch, tmp_path)
    parsed = broker_config(tmp_path, public_path)
    assert parsed.mcp.enabled is False

    off, _ = broker_main.build(parsed, client=stub_client())
    assert not any(getattr(r, "path", "").startswith("/mcp") for r in off.routes)
    assert not hasattr(off.state, "mcp_session_manager")

    on, _ = broker_main.build(
        dataclasses.replace(
            parsed, mcp=McpConfig(enabled=True, path="/tools", host="broker.example")
        ),
        client=stub_client(),
    )
    assert [r.path for r in on.routes if getattr(r, "path", "") == "/tools"] == [
        "/tools"
    ]
    assert on.state.mcp_session_manager is not None


def test_enabling_the_surface_without_the_extra_fails_at_boot(tmp_path, monkeypatch):
    """A deployment that switches the surface on without installing the extra
    is told so at startup. The alternative is a broker that reports healthy
    and 404s the endpoint its clients were configured to use."""
    import sys

    from tests.warden.test_app import build_with_mcp
    from warden.broker.config.loader import ConfigError
    from warden.broker.identity import Signer

    # What an absent extra looks like from create_app's import site, without
    # uninstalling anything: evict warden.broker.mcp so the import re-executes
    # the module, and poison `mcp` so its own `from mcp import types` raises
    # ImportError(name="mcp") -- which is the branch under test. Poisoning
    # warden.broker.mcp directly would NOT exercise it: that raises
    # ImportError(name="warden.broker.mcp"), a first-party defect create_app
    # deliberately re-raises rather than blaming on the extra.
    monkeypatch.delitem(sys.modules, "warden.broker.mcp", raising=False)
    monkeypatch.setitem(sys.modules, "mcp", None)
    signer = Signer.generate()
    with pytest.raises(ConfigError, match=r"warden\[mcp\]"):
        with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}):
            pass  # pragma: no cover


# --- The handshake era, driven raw -----------------------------------------
#
# Every test above goes through the SDK's Client, which negotiates 2026-07-28.
# That leaves the OTHER era -- the one a bare `POST /mcp` with no
# MCP-Protocol-Version header lands on, i.e. the default for anything that is
# not this SDK -- reachable only by raw POST. It is the era that skips the
# header rung `_is_internal_schema_lookup` depends on, and the era whose
# dispatcher puts `str(exc)` on the wire verbatim. `_era_gate` in
# warden/broker/mcp.py now refuses every request that would land there,
# before the SDK's own routing ever sees it -- the tests below are that
# gate's coverage.


LEGACY_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def raw_post(client, body, headers):
    """A bare `POST /mcp`, headers and all -- the only way to reach the
    handshake era, since the SDK's own Client always negotiates modern."""
    return client.post("/mcp", json=body, headers=headers)


def modern_list(routed_method="tools/list", version=None):
    """A modern-era `tools/list` envelope and its headers, built by hand.

    `routed_method` is what the `Mcp-Method` header claims, which the caller
    can make disagree with the body on purpose. `version` defaults to
    `LATEST_MODERN_VERSION`; a caller may pin it to any other member of
    `MODERN_PROTOCOL_VERSIONS` to prove that version is served too.
    """
    from mcp_types import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY
    from mcp_types.version import LATEST_MODERN_VERSION

    version = version or LATEST_MODERN_VERSION
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                PROTOCOL_VERSION_META_KEY: version,
                CLIENT_CAPABILITIES_META_KEY: {},
            }
        },
    }
    headers = {
        "MCP-Protocol-Version": version,
        "Mcp-Method": routed_method,
        "Accept": "application/json, text/event-stream",
    }
    return body, headers


def test_a_spoofed_routing_header_cannot_buy_an_unrecorded_probe(tmp_path):
    """The audit-evasion vector this guard shipped with, as a regression test.

    `_is_internal_schema_lookup` rests on the SDK rejecting a request whose
    `Mcp-Method` disagrees with its JSON-RPC method. That rung exists on the
    modern transport only: `StreamableHTTPSessionManager._handle_request`
    routes on `MCP-Protocol-Version` alone, and an absent or handshake-era
    version goes to the legacy transport, which never calls the classifier and
    never reads `Mcp-Method` at all. There, the header is unvalidated attacker
    input.

    Measured before the era check existed: this exact request was served and
    left ZERO audit records, so an unauthenticated caller could probe the
    enforcement point indefinitely by adding one header. `_era_gate` now
    refuses every case below outright, before the legacy transport (and
    therefore the spoofed `Mcp-Method`) is ever reached -- each must still
    leave exactly one record, now the era gate's own.
    """
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    payload = {"allow": True, "deny_reasons": []}
    for label, headers in [
        ("no routing header at all", {}),
        ("spoofed, no version header", {"Mcp-Method": "tools/call"}),
        ("spoofed, version pinned to the handshake era",
         {"Mcp-Method": "tools/call", "MCP-Protocol-Version": "2025-06-18"}),
        ("spoofed, version pinned to the oldest era",
         {"Mcp-Method": "tools/call", "MCP-Protocol-Version": "2024-11-05"}),
    ]:
        with build_with_mcp(tmp_path / label.replace(" ", "-"), signer, payload) as (
            client,
            audit,
        ):
            response = raw_post(client, LEGACY_LIST, headers)
            records = audit.records()
        assert response.json()["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION, label
        assert len(records) == 1, label
        assert records[0]["rule"] == "mcp.unsupported_protocol", label
        assert records[0]["action"] == {"type": "mcp_handshake"}, label


@pytest.mark.parametrize("version", sorted(HANDSHAKE_PROTOCOL_VERSIONS))
def test_every_handshake_era_version_is_refused_and_recorded(tmp_path, version):
    """The era check reads the SDK's own version tuple rather than a list of
    strings copied into this codebase, so a version added to
    HANDSHAKE_PROTOCOL_VERSIONS is covered the day the SDK ships it. Every
    one of them is refused by `_era_gate`, not merely "treated as a caller"
    -- that used to be the whole vulnerability: a handshake-era version was
    enough to reach the transport that skips `Mcp-Method` validation."""
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(
        tmp_path / version, signer, {"allow": True, "deny_reasons": []}
    ) as (client, audit):
        response = raw_post(
            client,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            {"MCP-Protocol-Version": version},
        )
        records = audit.records()
    assert response.json()["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION, version
    assert len(records) == 1, version


# --- Fix round 1: a duplicated MCP-Protocol-Version splits the gate and the
# SDK's own routing -----------------------------------------------------------
#
# _EraGate used to fold scope["headers"] into a dict, which keeps the LAST
# value for a repeated key. StreamableHTTPSessionManager._handle_request reads
# the SAME list with next(), which keeps the FIRST. Sent twice -- one
# handshake-era copy, one modern copy, in either order -- the two components
# disagreed about which one "the" version was: the gate could see modern and
# wave the request through, while the SDK's own routing underneath saw
# handshake-era and dispatched to the legacy transport anyway. That is the
# exact leg with no Mcp-Method validation and str(exc) on the wire, reachable
# again through the gate meant to close it off -- the same class of defect
# (two components disagreeing about one header) recurring one layer up.
#
# httpx accepts headers as a plain list of (name, value) pairs, which is the
# only way to actually send a header twice -- a dict or a Mapping can only
# ever carry one value per key.


def test_a_duplicated_protocol_version_header_is_refused_handshake_then_modern(
    tmp_path,
):
    """Handshake-era copy first, modern copy second -- the exact split that
    used to buy a served response: the old dict-fold read the LAST (modern)
    copy and passed the request through, while the SDK's own first-match
    routing underneath read the FIRST (handshake-era) copy and dispatched to
    the legacy transport regardless."""
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = client.post(
            "/mcp",
            json=LEGACY_LIST,
            headers=[
                (b"mcp-protocol-version", b"2024-11-05"),
                (b"mcp-protocol-version", b"2026-07-28"),
            ],
        )
        records = audit.records()
    assert response.json()["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION
    assert len(records) == 1
    assert records[0]["action"] == {"type": "mcp_handshake"}
    assert records[0]["rule"] == "mcp.unsupported_protocol"


def test_a_duplicated_protocol_version_header_is_refused_modern_then_handshake(
    tmp_path,
):
    """The other ordering. Both must refuse -- the gate does not get to pick
    a side just because the ambiguous copy it would have preferred happens to
    come first this time."""
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = client.post(
            "/mcp",
            json=LEGACY_LIST,
            headers=[
                (b"mcp-protocol-version", b"2026-07-28"),
                (b"mcp-protocol-version", b"2024-11-05"),
            ],
        )
        records = audit.records()
    assert response.json()["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION
    assert len(records) == 1
    assert records[0]["action"] == {"type": "mcp_handshake"}
    assert records[0]["rule"] == "mcp.unsupported_protocol"


def test_a_duplicated_protocol_version_header_refuses_even_when_both_copies_agree(
    tmp_path,
):
    """Pinned deliberately: two copies that both name the modern version are
    refused too, not served. No conforming client has a reason to send this
    header twice, so there is no legitimate case being narrowed here -- only
    an ambiguous one being closed, on principle, independent of what either
    copy says."""
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = client.post(
            "/mcp",
            json=LEGACY_LIST,
            headers=[
                (b"mcp-protocol-version", b"2026-07-28"),
                (b"mcp-protocol-version", b"2026-07-28"),
            ],
        )
        records = audit.records()
    assert response.json()["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION
    assert len(records) == 1
    assert records[0]["action"] == {"type": "mcp_handshake"}
    assert records[0]["rule"] == "mcp.unsupported_protocol"


def test_a_request_with_no_protocol_version_is_refused_and_recorded(tmp_path):
    """Absent is the handshake era's own signature, and that era is the one
    the SDK serves without validating Mcp-Method. An enforcement point does
    not let the party it contains pick the weaker of two code paths."""
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = raw_post(
            client, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, {}
        )
        assert response.json()["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION
        assert "2026-07-28" in response.text
        records = audit.records()
        assert len(records) == 1
        assert records[0]["action"] == {"type": "mcp_handshake"}
        assert records[0]["rule"] == "mcp.unsupported_protocol"


def test_an_unauthenticated_initialize_no_longer_discloses_capabilities(tmp_path):
    """Measured before this task, with a well-formed `initialize` (real
    clients always send protocolVersion/capabilities/clientInfo; an empty
    `params: {}` fails the SDK's own request-shape validation for an
    unrelated reason and was never a fair test of the disclosure): HTTP 200
    with a full InitializeResult -- capabilities and serverInfo both present
    -- and ZERO audit records, to a caller carrying no credential at all and
    no MCP-Protocol-Version header. The era gate now refuses the request
    before the SDK's initialize handler ever runs, so neither field reaches
    the wire and the attempt is recorded."""
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = raw_post(
            client,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "probe", "version": "0.0"},
                },
            },
            {},
        )
        assert "serverInfo" not in response.text
        assert "capabilities" not in response.text
        assert len(audit.records()) == 1


def test_the_sdk_client_still_works_end_to_end(tmp_path):
    """The whole bet: a real modern client is unaffected. Every request it
    sends -- server/discover included -- carries the modern version header."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        _,
    ):
        result = call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})
        assert result.is_error is False


def test_the_modern_era_rung_the_guard_rests_on_is_still_there(tmp_path):
    """Pins the SDK behaviour, so an upgrade that relaxes it fails loudly.

    On the modern era the guard is safe ONLY because
    `classify_inbound_request` refuses a `tools/list` whose `Mcp-Method` says
    `tools/call` before any handler runs -- so such a request can never be a
    caller's. If a future SDK let it through, the guard would answer a real
    caller's listing from the catalog with no spine call and no record. This
    asserts the refusal, and that a well-formed modern listing still reaches
    the spine (i.e. the guard does not over-fire on that era either).
    """
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    payload = {"allow": True, "deny_reasons": []}

    body, headers = modern_list(routed_method="tools/call")
    with build_with_mcp(tmp_path / "mismatched", signer, payload) as (client, audit):
        mismatched = client.post("/mcp", json=body, headers=headers)
        mismatched_records = audit.records()
    # -32020 is HEADER_MISMATCH, from the SDK's ladder, before dispatch.
    assert mismatched.json()["error"]["code"] == -32020
    assert mismatched_records == []

    body, headers = modern_list()
    with build_with_mcp(tmp_path / "agreeing", signer, payload) as (client, audit):
        agreeing = client.post("/mcp", json=body, headers=headers)
        agreeing_records = audit.records()
    # Warden's own refusal, from the spine, recorded.
    assert agreeing.json()["error"]["code"] == -32600
    assert [r["rule"] for r in agreeing_records] == ["unauthenticated"]


def test_the_surface_serves_post_only(tmp_path):
    """GET opens the protocol's standalone SSE stream and holds the connection
    open indefinitely with nothing recorded anywhere -- measured: no response
    in six seconds, before the route was narrowed. Nothing this deployment
    needs it: the SDK's client returns from handle_get_stream unless it holds
    a session id, and stateless mode never issues one.

    The GET is asserted against the route's own method set rather than by
    sending one. Sending it is what proves the hazard, and it is exactly why
    this test must not: with the narrowing removed, a live GET HANGS the suite
    instead of failing it -- verified by removing `methods=["POST"]`, at which
    point this file stopped terminating. DELETE is safe to send (the router
    answers it without reaching any stream) and covers the same mechanism
    end-to-end.

    The final POST is version-less `LEGACY_LIST`, which used to be served
    (200) and is refused by `_EraGate` now (400, still recorded once) -- this
    test only cares that a POST reaches SOME handler rather than the 405 a
    non-POST method gets, so the exact response it gets back is incidental to
    what this test is proving; the era gate's own tests pin that response.
    """
    from starlette.routing import Route

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        route = next(
            r
            for r in client.app.routes
            if isinstance(r, Route) and r.path == "/mcp"
        )
        assert route.methods == {"POST"}
        assert client.request("DELETE", "/mcp").status_code == 405
        assert client.post("/mcp", json=LEGACY_LIST).status_code == 400
        assert len(audit.records()) == 1


def test_the_inline_lookup_is_answered_from_the_catalog_not_with_an_empty_list(
    tmp_path,
):
    """The guarded path answers the SDK's own schema lookup from the catalog.

    Answering with an EMPTY listing -- the first shape of this guard -- makes
    `_tool_input_schema` find nothing and silently disables the SDK's
    `Mcp-Param-*`/body agreement check for every call. The catalog's names and
    schemas are what that lookup needs, and the result never reaches the wire:
    it is consumed inside the SDK to validate the call's own headers. So there
    is no disclosure to scope to a token, and no spine call to make.

    Driven at the handler rather than over HTTP because the condition is not
    reachable through a live request while two separate layers hold, not
    because of any inherent property of this handler: `_EraGate` (see
    `warden/broker/mcp.py`) refuses anything but an unambiguous, single-copy
    modern `MCP-Protocol-Version` before the SDK ever routes at all, and for
    whatever it lets through, `classify_inbound_request`'s own ladder rejects
    a `tools/list` whose Mcp-Method says `tools/call` before dispatch --
    exactly the rung the guard rests on (pinned by
    test_the_modern_era_rung_the_guard_rests_on_is_still_there). Either layer
    could regress independently of the other, so this test proves the guard's
    OWN behaviour is still correct even then, by constructing the condition
    directly rather than trusting that no live request can ever produce it.
    `Server`'s `get_request_handler` is public API and `session_manager.app`
    is its documented constructor argument.
    """
    import asyncio
    import dataclasses

    from mcp.server import ServerRequestContext
    from mcp.shared.exceptions import MCPError
    from mcp_types.version import LATEST_MODERN_VERSION

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    @dataclasses.dataclass
    class FakeRequest:
        headers: dict

    def context(**headers):
        return ServerRequestContext(
            session=None,
            lifespan_context=None,
            protocol_version=LATEST_MODERN_VERSION,
            method="tools/list",
            request=FakeRequest(headers=headers),
        )

    listed = []
    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        spine = client.app.state.spine
        real = spine.list_tools
        spine.list_tools = lambda *a: (listed.append(a), real(*a))[1]
        handler = client.app.state.mcp_session_manager.app.get_request_handler(
            "tools/list"
        ).handler

        internal = asyncio.run(
            handler(
                context(
                    **{
                        "mcp-protocol-version": LATEST_MODERN_VERSION,
                        "mcp-method": "tools/call",
                    }
                ),
                None,
            )
        )
        # The same condition without the era, i.e. what an attacker can forge
        # on the legacy transport: this must NOT be treated as internal.
        with pytest.raises(MCPError):
            asyncio.run(handler(context(**{"mcp-method": "tools/call"}), None))

        records = audit.records()

    names = sorted(tool.name for tool in internal.tools)
    assert names == sorted(client.app.state.spine._catalog.names())
    # Schemas, which are the only reason the SDK asked.
    assert all(tool.input_schema for tool in internal.tools)
    # The internal lookup asked the spine nothing; the forged one did.
    assert len(listed) == 1
    assert [r["rule"] for r in records] == ["unauthenticated"]


# --- Task 12: the filter is usability, never enforcement -------------------


def test_a_tool_withheld_from_the_listing_is_still_refused_by_rule_when_called(
    tmp_path,
):
    """The whole reason `list_tools` is allowed to filter at all.

    A token minted without "send_email" in `allowed_tools` has it withheld
    from `tools/list` -- but a caller that ignores the listing and calls it
    anyway does not meet a 404-shaped nothing. The call reaches the same
    spine as any other tool call, `tools.allowed` denies it by rule exactly
    as `test_a_denial_is_a_tool_error_naming_the_rule` proves for a
    different rule, and the attempt leaves an audit record naming it. If
    tools/list's filter were ever mistaken for enforcement -- e.g. the
    surface silently refusing an unlisted name before it reached the spine
    at all -- this would still pass on a passthrough that skipped the audit
    write, so all three parts (listing, error shape, record) are asserted
    together against the one call.
    """
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    # Named explicitly rather than relying on token_for's default staying
    # this shape: the precondition this test needs is that "send_email" is
    # NOT granted, and the catalog's other three tools are.
    token = token_for(
        signer, allowed_tools=["read_document", "query_customers", "http_fetch"]
    )
    with build_with_mcp(
        tmp_path, signer, {"allow": False, "deny_reasons": ["tools.allowed"]}
    ) as (client, audit):
        listing = list_tools(client, token)
        # (a) tools/list does not offer it.
        assert "send_email" not in {tool.name for tool in listing.tools}

        result = call_tool(
            client,
            token,
            "send_email",
            {"to": ["a@example.invalid"], "subject": "s", "body": "b"},
        )
        records = audit.records()

    # (b) A tool-execution error naming the rule -- not a protocol error
    # (nothing above raised), and not a silent empty result.
    assert result.is_error is True
    assert "tools.allowed" in result.content[0].text
    # (c) One audit record for the attempt, naming the same rule. The
    # listing above wrote nothing (usability, never enforcement), so this
    # is the only record.
    assert [r["rule"] for r in records] == ["tools.allowed"]
    assert [r["decision"] for r in records] == ["deny"]


@pytest.mark.parametrize("version", sorted(MODERN_PROTOCOL_VERSIONS))
def test_every_modern_era_version_is_served(tmp_path, version):
    """The surface serves exactly one protocol era -- the half of that claim
    `test_every_handshake_era_version_is_refused_and_recorded` does not
    cover.

    That test already proves every member of HANDSHAKE_PROTOCOL_VERSIONS is
    refused with -32022. This proves the complementary half: every member
    of MODERN_PROTOCOL_VERSIONS reaches the spine rather than being refused
    by `_EraGate` -- drawn from `mcp_types.version`, not hardcoded, so the
    day the SDK adds a second modern revision this test says whether it is
    actually served instead of silently passing either way.

    Sent unauthenticated on purpose: that is what makes "served" observable
    without a token. `_EraGate` refuses an unserved version with -32022 and
    records rule "mcp.unsupported_protocol" before the SDK's own routing
    ever runs. A version it lets through instead reaches the spine, which
    then refuses it for lack of a credential -- -32600, rule
    "unauthenticated" (the same pair
    `test_the_modern_era_rung_the_guard_rests_on_is_still_there` pins for
    LATEST_MODERN_VERSION alone). Reaching THAT refusal, for every version
    in the modern set, is the proof the era gate let each one through.
    """
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    body, headers = modern_list(version=version)
    with build_with_mcp(
        tmp_path / version, signer, {"allow": True, "deny_reasons": []}
    ) as (client, audit):
        response = raw_post(client, body, headers)
        records = audit.records()

    assert response.json()["error"]["code"] == -32600, version
    assert [r["rule"] for r in records] == ["unauthenticated"], version
