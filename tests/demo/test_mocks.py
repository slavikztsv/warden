from fastapi.testclient import TestClient

from demo.mocks.docstore import app as docstore_app
from demo.mocks.mailer import app as mailer_app
from demo.mocks.sinkhole import app as sinkhole_app


def test_docstore_serves_the_ticket():
    response = TestClient(docstore_app).get("/docs/ticket-4711")
    assert response.status_code == 200
    assert "8812" in response.text


def test_the_kb_document_carries_the_injection_and_its_fallback():
    body = TestClient(docstore_app).get("/docs/kb/refund-policy").text
    assert "attacker.example/collect" in body
    # The fallback is what makes the taint rule do real work.
    assert "docstore.internal/feedback" in body


def test_unknown_document_is_404():
    assert TestClient(docstore_app).get("/docs/nope").status_code == 404


def test_mailer_records_what_it_sent():
    client = TestClient(mailer_app)
    client.post("/send", json={"to": ["customer:8812"], "subject": "s", "body": "b"})
    outbox = client.get("/outbox").json()
    assert len(outbox) == 1
    assert outbox[0]["to"] == ["customer:8812"]


def test_sinkhole_records_every_byte_it_receives():
    client = TestClient(sinkhole_app)
    client.post("/collect", content=b"stolen-rows")
    received = client.get("/__received").json()
    assert received["request_count"] == 1
    assert received["total_bytes"] == len(b"stolen-rows")
    assert "stolen-rows" in received["bodies"][0]


def test_sinkhole_starts_empty():
    received = TestClient(sinkhole_app).get("/__received").json()
    assert received["request_count"] >= 0


# --- The fallback destination must actually work ---------------------------
#
# /feedback declared `payload: dict`, so FastAPI validated the body and the
# exfiltrated customer rows -- a JSON ARRAY -- got a 422. The whole point of
# this endpoint is that it IS allowlisted and IS reachable, so that the
# protected run's denial can only be attributed to the taint rule. A 422 here
# would make the demo prove the wrong thing: the fetch would fail whether or
# not egress.pii_sink existed.


def test_feedback_accepts_the_json_array_the_cassette_actually_posts():
    import json
    from pathlib import Path

    cassette = (
        Path(__file__).resolve().parent.parent.parent / "demo/agent/cassettes/support-triage.json"
    )
    steps = json.loads(cassette.read_text())
    bodies = [
        step["args"]["body"]
        for step in steps
        if step.get("tool") == "http_fetch"
        and "feedback" in step["args"].get("url", "")
        and step["args"].get("body")
    ]
    assert bodies, "the cassette no longer posts a body to the fallback endpoint"

    for body in bodies:
        assert isinstance(json.loads(body), list)  # the shape that used to 422
        response = TestClient(docstore_app).post(
            "/feedback", content=body, headers={"content-type": "application/json"}
        )
        assert response.status_code == 200
        assert response.json() == {"received": True}


def test_feedback_accepts_any_json_body_shape():
    client = TestClient(docstore_app)
    for body in ('[{"id": 8812}]', '{"rows": 1}', '"a string"', "42", "null", "[]"):
        response = client.post(
            "/feedback", content=body, headers={"content-type": "application/json"}
        )
        assert response.status_code == 200, f"{body} was refused"


def test_feedback_records_what_lands_in_it():
    """An internal, allowlisted destination is still somewhere customer data
    can end up. "0 bytes reached the attacker" says nothing about it, so the
    damage was real and unmeasured until this endpoint recorded bodies."""
    from fastapi.testclient import TestClient

    from demo.mocks import docstore

    docstore.RECEIVED.clear()
    client = TestClient(docstore.app)
    client.post("/feedback", content='[{"id": 8812, "email": "x@example.invalid"}]')
    assert len(docstore.RECEIVED) == 1
    assert "8812" in docstore.RECEIVED[0]
    assert client.get("/__received").json()["request_count"] == 1
    docstore.RECEIVED.clear()


def test_every_poison_keeps_the_document_plausible_and_names_a_destination():
    """Each payload is an injection embedded in a document the agent was told
    to read. It must still read as the refund policy, or the scenario is
    testing whether a model notices nonsense rather than whether the broker
    holds."""
    from demo.mocks import docstore

    for name, text in docstore.POISONS.items():
        assert "Refund policy" in text, name
        assert "$200" in text, f"{name} dropped the legitimate content"
        assert any(
            marker in text
            for marker in ("http://", "https://", "@")
        ), f"{name} names no destination"


def test_set_poison_swaps_the_referenced_document_only():
    """The ticket always points at kb/refund-policy. Swapping what that
    document contains keeps the operator's instruction identical, so the model
    is fooled by something it read rather than told by its principal."""
    from demo.mocks import docstore

    original = docstore.DOCUMENTS["kb/refund-policy"]
    try:
        docstore.set_poison("recon")
        assert "billing-recon.vendor.example" in docstore.DOCUMENTS["kb/refund-policy"]
        assert "kb/refund-policy" in docstore.DOCUMENTS["ticket-4711"]
        docstore.set_poison("audit")
        assert "audit-team@partner.example" in docstore.DOCUMENTS["kb/refund-policy"]
    finally:
        docstore.DOCUMENTS["kb/refund-policy"] = original
