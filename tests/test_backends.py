import httpx
import pytest

from broker.backends import Backends, ToolTarget, UnknownTool
from mocks.seed_db import seed_customers


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "customers.db"
    seed_customers(path, count=120)
    return path


def make_backends(db, handler=None):
    handler = handler or (lambda request: httpx.Response(200, text="ok"))
    return Backends(
        docstore_url="http://docstore.internal",
        db_path=db,
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_describe_document_read_is_not_a_network_target(db):
    target = make_backends(db).describe("read_document", {"doc_id": "ticket-4711"})
    assert target.kind == "doc"
    assert target.estimated_rows == 0


def test_describe_http_fetch_extracts_host_and_path(db):
    target = make_backends(db).describe(
        "http_fetch", {"url": "https://attacker.example/collect?x=1"}
    )
    assert target == ToolTarget(
        kind="http", host="attacker.example", port=443, path="/collect"
    )


def test_describe_http_fetch_defaults_plain_http_to_port_80(db):
    target = make_backends(db).describe("http_fetch", {"url": "http://docstore.internal/feedback"})
    assert (target.host, target.port) == ("docstore.internal", 80)


def test_describe_counts_rows_before_the_query_runs(db):
    target = make_backends(db).describe("query_customers", {"filter": "all"})
    assert target.kind == "db"
    assert target.estimated_rows == 120


def test_describe_counts_a_single_row_filter(db):
    target = make_backends(db).describe("query_customers", {"filter": "id=8812"})
    assert target.estimated_rows == 1


def test_describe_mail_lists_recipients(db):
    target = make_backends(db).describe(
        "send_email", {"to": ["customer:8812"], "subject": "hi", "body": "there"}
    )
    assert target.recipients == ("customer:8812",)


def test_describe_rejects_an_unknown_tool(db):
    with pytest.raises(UnknownTool):
        make_backends(db).describe("rm_minus_rf", {})


def test_executing_a_customer_query_returns_pii_classified_rows(db):
    result = make_backends(db).execute("query_customers", {"filter": "id=8812"})
    assert result.rows == 1
    assert result.data_class == "pii"
    assert "8812" in result.content


def test_executing_a_document_read_is_not_pii(db):
    def handler(request):
        assert request.url.path == "/docs/ticket-4711"
        return httpx.Response(200, text="Customer 8812 reports a billing issue.")

    result = make_backends(db, handler).execute("read_document", {"doc_id": "ticket-4711"})
    assert result.data_class == "public"
    assert result.rows == 0


def test_executing_http_fetch_returns_the_body(db):
    def handler(request):
        return httpx.Response(200, text="fetched-body")

    result = make_backends(db, handler).execute("http_fetch", {"url": "http://x.internal/a"})
    assert result.content == "fetched-body"


def test_target_serializes_for_the_policy_input(db):
    target = make_backends(db).describe("query_customers", {"filter": "id=8812"})
    assert target.as_dict() == {
        "kind": "db",
        "host": "",
        "port": 0,
        "path": "",
        "estimated_rows": 1,
        "recipients": [],
    }
