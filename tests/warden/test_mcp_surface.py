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
    the tool catalog on its way there."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    calls = []
    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        spine = client.app.state.spine
        real = spine.handle_tool_call
        spine.handle_tool_call = lambda *a: (calls.append(a), real(*a))[1]
        result = call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})

    assert result.is_error is False
    assert len(calls) == 1
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
    assert str(records[0]["seq"]) in text
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
    """
    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    payload = {"allow": True, "deny_reasons": []}

    with build_with_mcp(tmp_path / "unset", signer, payload, host="") as (client, _):
        refused = client.post("/mcp", json=body)
    assert refused.status_code == 421

    with build_with_mcp(tmp_path / "named", signer, payload, host="testserver") as (
        client,
        _,
    ):
        accepted = client.post("/mcp", json=body)
    assert accepted.status_code != 421


# --- Rendering, without a transport ----------------------------------------


def test_no_rendering_repeats_the_exception_text_it_was_handed(tmp_path):
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


def test_every_kind_has_a_rendering(tmp_path):
    """A Kind with no branch must be a protocol error, never an
    AttributeError escaping into the transport."""
    from mcp.shared.exceptions import MCPError

    from warden.broker.mcp import render_call
    from warden.broker.spine import Kind, Outcome

    for kind in Kind:
        if kind is Kind.EXECUTED:
            continue
        with contextlib.suppress(MCPError):
            assert render_call(Outcome(kind=kind, message="m")).is_error is True


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
    # uninstalling anything: a None in sys.modules makes the import raise
    # ImportError, which is the branch under test.
    monkeypatch.setitem(sys.modules, "warden.broker.mcp", None)
    signer = Signer.generate()
    with pytest.raises(ConfigError, match=r"warden\[mcp\]"):
        with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}):
            pass  # pragma: no cover
