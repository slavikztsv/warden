import httpx
import pytest
from fastapi.testclient import TestClient

from broker.app import create_app
from broker.audit import AuditLog
from broker.backends import Backends
from broker.control import create_control_app
from broker.identity import Signer, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.taint import TaintTracker
from mocks.seed_db import seed_customers


@pytest.fixture
def signer():
    return Signer.generate()


def build(tmp_path, signer, opa_payload, backend_handler=None):
    db = tmp_path / "customers.db"
    seed_customers(db, count=120)

    def opa_handler(request):
        return httpx.Response(200, json={"result": opa_payload})

    backend_handler = backend_handler or (lambda request: httpx.Response(200, text="doc-body"))
    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=TaintTracker(),
        audit=audit,
        backends=Backends(
            docstore_url="http://docstore.internal",
            db_path=db,
            mailer_url="http://mailer.internal",
            client=httpx.Client(transport=httpx.MockTransport(backend_handler)),
        ),
        policy_digest="sha256:test",
    )
    return TestClient(app), audit


def token_for(signer, **overrides):
    fields = dict(
        agent_id="triage-bot",
        task_id="4711",
        purpose="support-triage",
        allowed_tools=["read_document", "query_customers", "http_fetch"],
        data_classes=["public"],
        counterparties=["customer:8812"],
    )
    fields.update(overrides)
    return signer.mint(**fields)


def invoke(client, token, tool, args):
    return client.post(
        f"/v1/tools/{tool}/invoke",
        json={"args": args},
        headers={"Authorization": f"Bearer {token}"},
    )


def test_allowed_call_executes_and_returns_content(tmp_path, signer):
    client, _ = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "ticket-4711"})
    assert response.status_code == 200
    assert response.json()["content"] == "doc-body"


def test_denied_call_returns_a_structured_error(tmp_path, signer):
    client, _ = build(
        tmp_path, signer, {"allow": False, "deny_reasons": ["egress.pii_sink"]}
    )
    response = invoke(client, token_for(signer), "http_fetch", {"url": "http://x.internal/a"})
    assert response.status_code == 403
    assert response.json() == {
        "error": "policy_denied",
        "rule": "egress.pii_sink",
        "message": "Denied by policy rule egress.pii_sink.",
    }


def test_denied_call_does_not_execute_the_backend(tmp_path, signer):
    calls = []

    def backend_handler(request):
        calls.append(request.url)
        return httpx.Response(200, text="should-not-happen")

    client, _ = build(
        tmp_path,
        signer,
        {"allow": False, "deny_reasons": ["egress.allowlist"]},
        backend_handler,
    )
    invoke(client, token_for(signer), "http_fetch", {"url": "http://attacker.example/collect"})
    assert calls == []


def test_missing_token_is_rejected(tmp_path, signer):
    client, _ = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    response = client.post("/v1/tools/read_document/invoke", json={"args": {}})
    assert response.status_code == 401


def test_expired_token_is_rejected(tmp_path, signer):
    client, _ = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    stale = token_for(signer)
    import broker.app as app_module

    original = app_module.now
    app_module.now = lambda: 10**12
    try:
        response = invoke(client, stale, "read_document", {"doc_id": "x"})
    finally:
        app_module.now = original
    assert response.status_code == 401


def test_unknown_tool_is_denied_before_any_policy_query(tmp_path, signer):
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    response = invoke(client, token_for(signer), "rm_minus_rf", {})
    assert response.status_code == 403
    assert audit.records()[-1]["rule"] == "tools.allowed"


def test_every_decision_is_audited_with_an_intact_chain(tmp_path, signer):
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    invoke(client, token_for(signer), "read_document", {"doc_id": "b"})
    records = audit.records()
    assert len(records) == 2
    assert [r["decision"] for r in records] == ["allow", "allow"]
    assert audit.verify_chain() == (True, None)


def test_audit_record_precedes_execution(tmp_path, signer):
    order = []

    def backend_handler(request):
        order.append("executed")
        return httpx.Response(200, text="body")

    client, audit = build(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, backend_handler
    )
    original_append = audit.append

    def spy(**kwargs):
        order.append("audited")
        return original_append(**kwargs)

    audit.append = spy
    invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    assert order == ["audited", "executed"]


def test_reading_customers_taints_the_task_for_later_calls(tmp_path, signer):
    seen = []

    def opa_handler(request):
        seen.append(request.read())
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    db = tmp_path / "customers.db"
    seed_customers(db, count=120)
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=TaintTracker(),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        backends=Backends(
            docstore_url="http://docstore.internal",
            db_path=db,
            mailer_url="http://mailer.internal",
            client=httpx.Client(
                transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x"))
            ),
        ),
        policy_digest="sha256:test",
    )
    client = TestClient(app)
    token = token_for(signer)
    invoke(client, token, "query_customers", {"filter": "id=8812"})
    invoke(client, token, "http_fetch", {"url": "http://x.internal/a"})

    import json

    second_input = json.loads(seen[1])["input"]
    assert second_input["task_state"]["data_classes_held"] == ["pii"]
    assert second_input["task_state"]["rows_returned_so_far"] == 1


def test_audit_write_failure_refuses_the_action(tmp_path, signer):
    calls = []

    def backend_handler(request):
        calls.append(request.url)
        return httpx.Response(200, text="body")

    client, audit = build(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, backend_handler
    )

    def explode(**kwargs):
        raise OSError("disk full")

    audit.append = explode
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    assert response.status_code == 503
    assert response.json()["error"] == "audit_unavailable"
    assert calls == []


def test_control_plane_mints_a_usable_token(signer):
    client = TestClient(create_control_app(signer=signer))
    response = client.post(
        "/v1/tokens",
        json={
            "agent_id": "triage-bot",
            "task_id": "4711",
            "purpose": "support-triage",
            "allowed_tools": ["read_document"],
            "data_classes": ["public"],
            "counterparties": ["customer:8812"],
        },
    )
    assert response.status_code == 200
    token = Verifier(signer.public_key_pem()).verify(response.json()["token"])
    assert token.purpose == "support-triage"


def test_agent_app_does_not_expose_the_minting_route(tmp_path, signer):
    client, _ = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    assert client.post("/v1/tokens", json={}).status_code == 404


# --- Carry-forward 1: backend failures must become audited denials, not bare 500s. ---


def test_describe_failure_is_audited_as_malformed_input(tmp_path, signer):
    """A query_customers filter that backends.describe() cannot parse (a
    ValueError from the int() call in _where()) must not surface as an
    unhandled 500. No decision was ever reached, so it is audited as a deny
    under input.malformed, and the caller gets a structured 502."""
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    response = invoke(client, token_for(signer), "query_customers", {"filter": "id=abc"})
    assert response.status_code == 502
    body = response.json()
    assert body["error"] == "backend_error"
    assert "message" in body

    records = audit.records()
    assert len(records) == 1
    assert records[-1]["decision"] == "deny"
    assert records[-1]["rule"] == "input.malformed"


def test_execute_http_status_failure_becomes_backend_error_without_double_audit(
    tmp_path, signer
):
    """backends.execute() raises httpx.HTTPStatusError when the http_fetch
    destination answers non-2xx. The decision was already made and durably
    audited as an allow before execute() ran, so this must not write a
    second decision record -- only the 502 changes, the original allow
    record stands alone."""

    def backend_handler(request):
        return httpx.Response(500, text="upstream on fire")

    client, audit = build(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, backend_handler
    )
    response = invoke(client, token_for(signer), "http_fetch", {"url": "http://x.internal/a"})
    assert response.status_code == 502
    body = response.json()
    assert body["error"] == "backend_error"
    assert "message" in body

    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "allow"


def test_execute_connection_failure_becomes_backend_error(tmp_path, signer):
    """A connection-level httpx failure (timeout, refused connection, ...)
    during execute() must be caught the same way as an HTTP status error --
    it is still an httpx.HTTPError -- rather than escaping as a 500."""

    def backend_handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    client, audit = build(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, backend_handler
    )
    response = invoke(client, token_for(signer), "http_fetch", {"url": "http://x.internal/a"})
    assert response.status_code == 502
    assert response.json()["error"] == "backend_error"

    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "allow"


# --- Beyond-the-brief verification ---


def _build_with_spies(tmp_path, signer):
    """Like build(), but exposes the pdp and backends instances wrapped
    with call-recording spies, so a test can prove a stage was never
    reached rather than merely asserting the final status code."""
    db = tmp_path / "customers.db"
    seed_customers(db, count=5)

    def opa_handler(request):
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    def backend_handler(request):
        return httpx.Response(200, text="doc-body")

    pdp = PolicyDecisionPoint(
        "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
    )
    backends = Backends(
        docstore_url="http://docstore.internal",
        db_path=db,
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(backend_handler)),
    )

    decide_calls = []
    original_decide = pdp.decide

    def decide_spy(input_doc):
        decide_calls.append(input_doc)
        return original_decide(input_doc)

    pdp.decide = decide_spy

    describe_calls = []
    original_describe = backends.describe

    def describe_spy(tool, args):
        describe_calls.append((tool, args))
        return original_describe(tool, args)

    backends.describe = describe_spy

    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=pdp,
        taint=TaintTracker(),
        audit=audit,
        backends=backends,
        policy_digest="sha256:test",
    )
    return TestClient(app), decide_calls, describe_calls


def test_unverified_token_never_reaches_pdp_or_backend(tmp_path, signer):
    """A token signed by a key the broker does not trust must be rejected
    before the PDP or the backend describe() step is ever touched -- proven
    here by recording calls rather than just checking the status code."""
    client, decide_calls, describe_calls = _build_with_spies(tmp_path, signer)
    untrusted_signer = Signer.generate()
    bogus_token = token_for(untrusted_signer)

    response = invoke(client, bogus_token, "read_document", {"doc_id": "x"})

    assert response.status_code == 401
    assert describe_calls == []
    assert decide_calls == []


def test_expired_token_never_reaches_pdp_or_backend(tmp_path, signer):
    """Same proof as above, for an expired-but-otherwise-valid token."""
    client, decide_calls, describe_calls = _build_with_spies(tmp_path, signer)
    stale = token_for(signer)

    import broker.app as app_module

    original = app_module.now
    app_module.now = lambda: 10**12
    try:
        response = invoke(client, stale, "read_document", {"doc_id": "x"})
    finally:
        app_module.now = original

    assert response.status_code == 401
    assert describe_calls == []
    assert decide_calls == []


def test_policy_input_task_state_is_the_pre_execution_snapshot(tmp_path, signer):
    """The row bound OPA enforces is already_read + about_to_read. That only
    works if task_state in the policy input is the snapshot taken BEFORE
    this call executes. Prove it directly: a single query_customers call
    that returns 120 rows must still report rows_returned_so_far == 0 to
    the PDP for that same call, because taint.record_read() has not run
    yet when decide() is invoked."""
    import json

    seen = []

    def opa_handler(request):
        seen.append(json.loads(request.read()))
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    db = tmp_path / "customers.db"
    seed_customers(db, count=120)
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=TaintTracker(),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        backends=Backends(
            docstore_url="http://docstore.internal",
            db_path=db,
            mailer_url="http://mailer.internal",
            client=httpx.Client(
                transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x"))
            ),
        ),
        policy_digest="sha256:test",
    )
    client = TestClient(app)
    response = invoke(client, token_for(signer), "query_customers", {"filter": "all"})

    assert response.status_code == 200
    assert response.json()["rows"] == 120
    assert seen[0]["input"]["task_state"]["rows_returned_so_far"] == 0
