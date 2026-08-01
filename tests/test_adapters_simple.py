"""The three adapters that are a lift of one backends.py branch each."""

from __future__ import annotations

import httpx
import pytest

from broker.adapters.docstore import DocstoreAdapter
from broker.adapters.http import HttpAdapter
from broker.adapters.mail import MailAdapter


def recording_client(record: list) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        record.append((request.method, str(request.url), request.content))
        return httpx.Response(200, text="ok")

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_docstore_describe_uses_the_bare_document_id():
    """Not the resolved request path. describe() and execute() disagree on
    purpose: resolving here turns read_document(ticket-4711) into
    read_document(/docs/ticket-4711) in the replay and re-flows the padding."""
    adapter = DocstoreAdapter(
        binding={"base_url": "http://docstore.internal", "data_class": "public"},
        client=recording_client([]),
    )
    target = adapter.describe({"doc_id": "ticket-4711"})
    assert target.as_dict() == {
        "kind": "doc", "host": "", "port": 0, "path": "ticket-4711",
        "estimated_rows": 0, "recipients": [], "subjects": [],
    }


def test_docstore_execute_resolves_the_url():
    calls: list = []
    adapter = DocstoreAdapter(
        binding={"base_url": "http://docstore.internal/", "data_class": "public"},
        client=recording_client(calls),
    )
    result = adapter.execute({"doc_id": "kb/refund-policy"})
    assert calls == [("GET", "http://docstore.internal/docs/kb/refund-policy", b"")]
    assert result.data_class == "public"


def test_http_describe_parses_host_port_and_path():
    adapter = HttpAdapter(binding={"data_class": "public"}, client=recording_client([]))
    assert adapter.describe({"url": "https://attacker.example/collect"}).as_dict() == {
        "kind": "http", "host": "attacker.example", "port": 443, "path": "/collect",
        "estimated_rows": 0, "recipients": [], "subjects": [],
    }
    # A bare host normalises to "/", as urlsplit gives "".
    assert adapter.describe({"url": "http://docstore.internal"}).as_dict()["path"] == "/"
    assert adapter.describe({"url": "http://docstore.internal"}).as_dict()["port"] == 80


def test_http_execute_is_a_get_without_a_body_and_a_post_with_one():
    """Exfiltration is a write. With a bare GET the sinkhole records zero
    bytes and the unprotected profile has nothing to show."""
    calls: list = []
    adapter = HttpAdapter(binding={"data_class": "public"}, client=recording_client(calls))
    adapter.execute({"url": "http://x/a"})
    adapter.execute({"url": "http://x/b", "body": "rows"})
    adapter.execute({"url": "http://x/c", "body": None})
    assert [(m, u) for m, u, _ in calls] == [
        ("GET", "http://x/a"), ("POST", "http://x/b"), ("GET", "http://x/c"),
    ]
    assert calls[1][2] == b"rows"


def test_mail_describe_lists_recipients():
    adapter = MailAdapter(
        binding={"base_url": "http://mailer.internal",
                 "fields": ["to", "subject", "body"]},
        client=recording_client([]),
    )
    target = adapter.describe({"to": ["customer:8812"], "subject": "s", "body": "b"})
    assert target.as_dict()["kind"] == "mail"
    assert target.as_dict()["recipients"] == ["customer:8812"]


def test_mail_sends_only_declared_fields():
    """The live hole: backends.py posts the WHOLE args dict, so an undeclared
    cc rides along on a call whose audited recipients is the approved one.
    unknown_args=reject stops it at the door; this stops it at the wire, and
    both are wanted -- the schema is config and could be relaxed."""
    calls: list = []
    adapter = MailAdapter(
        binding={"base_url": "http://mailer.internal",
                 "fields": ["to", "subject", "body"]},
        client=recording_client(calls),
    )
    adapter.execute({"to": ["customer:8812"], "subject": "s", "body": "b",
                     "cc": ["attacker@evil.example"]})
    import json
    method, url, body = calls[0]
    assert method == "POST"
    assert url == "http://mailer.internal/send"
    sent = json.loads(body)
    assert sent == {"to": ["customer:8812"], "subject": "s", "body": "b"}
    assert "cc" not in sent


def test_mail_respects_custom_path():
    """Non-default path binding is exercised and honored."""
    calls: list = []
    adapter = MailAdapter(
        binding={"base_url": "http://mailer.internal",
                 "path": "/deliver",
                 "fields": ["to", "subject", "body"]},
        client=recording_client(calls),
    )
    adapter.execute({"to": ["user@example.com"], "subject": "test", "body": "msg"})
    method, url, body = calls[0]
    assert method == "POST"
    assert url == "http://mailer.internal/deliver"
    import json
    sent = json.loads(body)
    assert sent == {"to": ["user@example.com"], "subject": "test", "body": "msg"}


def test_mail_records_no_read():
    adapter = MailAdapter(
        binding={"base_url": "http://m", "fields": ["to", "subject", "body"]},
        client=recording_client([]),
    )
    assert adapter.execute({"to": [], "subject": "", "body": ""}).data_class is None


def test_docstore_execute_propagates_http_errors():
    """Ensure non-2xx responses raise HTTPStatusError, not silently ignored."""
    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    client = httpx.Client(transport=httpx.MockTransport(failing_handler))
    adapter = DocstoreAdapter(
        binding={"base_url": "http://docstore.internal", "data_class": "public"},
        client=client,
    )
    with pytest.raises(httpx.HTTPStatusError):
        adapter.execute({"doc_id": "ticket-1"})


def test_http_execute_propagates_http_errors():
    """Ensure non-2xx responses raise HTTPStatusError."""
    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Server Error")

    client = httpx.Client(transport=httpx.MockTransport(failing_handler))
    adapter = HttpAdapter(
        binding={"data_class": "public"},
        client=client,
    )
    with pytest.raises(httpx.HTTPStatusError):
        adapter.execute({"url": "http://example.com"})


def test_mail_execute_propagates_http_errors():
    """Ensure non-2xx responses raise HTTPStatusError."""
    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Mail Service Error")

    client = httpx.Client(transport=httpx.MockTransport(failing_handler))
    adapter = MailAdapter(
        binding={"base_url": "http://mailer.internal", "fields": ["to", "subject", "body"]},
        client=client,
    )
    with pytest.raises(httpx.HTTPStatusError):
        adapter.execute({"to": ["user@example.com"], "subject": "test", "body": "msg"})


@pytest.mark.parametrize("adapter_cls,kind", [
    (DocstoreAdapter, "doc"), (HttpAdapter, "http"), (MailAdapter, "mail"),
])
def test_each_declares_its_target_kind(adapter_cls, kind):
    assert adapter_cls.target_kind == kind
