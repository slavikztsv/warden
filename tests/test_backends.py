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


def test_executing_http_fetch_raises_on_a_failed_response(db):
    def handler(request):
        return httpx.Response(500, text="internal server error from destination")

    with pytest.raises(httpx.HTTPStatusError):
        make_backends(db, handler).execute("http_fetch", {"url": "http://x.internal/a"})


def test_executing_http_fetch_with_a_body_posts_it(db):
    """Exfiltration is a write, not a read: an http_fetch carrying a body
    must POST that body to the target rather than performing a bodiless
    GET, or the sinkhole records zero bytes and the demo's beat 1 -- the
    data genuinely leaving -- has nothing to show."""
    seen = {}

    def handler(request):
        seen["method"] = request.method
        seen["body"] = request.read().decode()
        return httpx.Response(200, text="delivered")

    result = make_backends(db, handler).execute(
        "http_fetch", {"url": "http://x.internal/a", "body": "customer-rows"}
    )
    assert seen["method"] == "POST"
    assert seen["body"] == "customer-rows"
    assert result.content == "delivered"


def test_target_serializes_for_the_policy_input(db):
    target = make_backends(db).describe("query_customers", {"filter": "id=8812"})
    assert target.as_dict() == {
        "kind": "db",
        "host": "",
        "port": 0,
        "path": "",
        "subjects": ["customer:8812"],
        "estimated_rows": 1,
        "recipients": [],
    }


def test_describe_resolves_which_subjects_a_query_names(db):
    """R7 compares these against the token's counterparties.

    Only an `id=` filter names a bounded set. Everything else says so with "*"
    rather than enumerating — resolving `plan=pro` into ids would mean reading
    the rows in order to decide whether the read is allowed.
    """
    backends = make_backends(db)
    assert backends.describe(
        "query_customers", {"filter": "id=8812"}).subjects == ("customer:8812",)
    assert backends.describe(
        "query_customers", {"filter": "all"}).subjects == ("*",)
    assert backends.describe(
        "query_customers", {"filter": "pro"}).subjects == ("*",)
    # A malformed id raises out of describe(), which the broker maps to
    # input.malformed (broker/app.py) — refused with a reason, not guessed at.
    import pytest

    with pytest.raises(ValueError):
        backends.describe("query_customers", {"filter": "id=notanumber"})


def test_only_a_db_target_carries_subjects(db):
    """A non-db target has no subjects, and the policy only validates the field
    for db targets — so a doc or mail target must not invent one."""
    backends = make_backends(db)
    for tool, args in (
        ("read_document", {"doc_id": "ticket-4711"}),
        ("send_email", {"to": ["customer:8812"], "subject": "s", "body": "b"}),
        ("http_fetch", {"url": "http://x.internal/a"}),
    ):
        assert backends.describe(tool, args).subjects == (), tool
