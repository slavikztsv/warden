"""The spine's contract: every variant reachable, rendering pure."""

from __future__ import annotations

from warden.broker.app import _render
from warden.broker.spine import (
    AUDIT_UNAVAILABLE,
    DENIED,
    FAULT,
    Kind,
    Outcome,
)


def test_every_kind_has_an_http_rendering():
    """Totality, and the right status per Kind. A Kind nobody rendered is a
    variant that 500s in production; asserting only "no ValueError" is not
    enough -- moving AUDIT_UNAVAILABLE_ON_ALLOW from the 503 group to the
    502 group would still pass that weaker check, and this table catches
    it."""
    expected_status = {
        Kind.UNAUTHENTICATED: 401,
        Kind.AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED: 503,
        Kind.AUDIT_UNAVAILABLE_ON_ALLOW: 503,
        Kind.AUDIT_UNAVAILABLE_ON_DENY: 503,
        Kind.DESCRIBE_BACKEND_FAULT: 502,
        Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW: 502,
        Kind.TAINT_REJECTED_AFTER_EXECUTE: 502,
        Kind.POLICY_DENIED: 403,
        Kind.UNKNOWN_TOOL_DENIED: 403,
        Kind.MALFORMED_BODY_DENIED: 403,
        Kind.SCHEMA_INVALID_DENIED: 403,
        Kind.DESCRIBE_CLIENT_ERROR_DENIED: 403,
    }
    # LISTED is a ListOutcome, not an Outcome, rendered by list surfaces, not
    # this table. EXECUTED needs a real ToolResult -- covered by test_app.py.
    skipped = {Kind.LISTED, Kind.EXECUTED}
    assert set(expected_status) | skipped == set(Kind), (
        "a Kind is missing from both the status table and the skip set"
    )
    for kind, status in expected_status.items():
        response = _render(Outcome(kind=kind, rule="r", message="m"))
        assert response.status_code == status, f"{kind} rendered as {response.status_code}, expected {status}"


def test_the_three_groupings_are_disjoint_and_cover_every_failure():
    assert not (DENIED & AUDIT_UNAVAILABLE)
    assert not (DENIED & FAULT)
    assert not (AUDIT_UNAVAILABLE & FAULT)
    accounted = DENIED | AUDIT_UNAVAILABLE | FAULT | {
        Kind.EXECUTED, Kind.LISTED, Kind.UNAUTHENTICATED
    }
    assert set(Kind) == accounted


def test_rendering_an_outcome_twice_has_no_side_effects(tmp_path):
    """Rendering is pure. If a renderer applied the taint update or wrote the
    audit record, two surfaces could apply it twice, or in a different order
    relative to each other, and the row budget would drift with no signal."""
    from tests.warden.test_app import build, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    spine = client.app.state.spine

    token = token_for(signer)
    outcome = spine.handle_tool_call(token, "read_document", {"doc_id": "a"})
    # Otherwise a future change that made this call deny (or fault) would
    # silently gut the test: any outcome renders idempotently by accident if
    # nothing was ever written for it to duplicate.
    assert outcome.kind is Kind.EXECUTED

    before_records = len(audit.records())
    before_state = spine._taint.snapshot("4711")

    _render(outcome)
    _render(outcome)

    assert len(audit.records()) == before_records
    assert spine._taint.snapshot("4711") == before_state


def test_a_pdp_outage_denies_rather_than_faulting(tmp_path):
    """pdp.unavailable is POLICY_DENIED carrying that rule -- a 403, not a
    5xx. It is the one deny rule the policy bundle does not produce, and
    mapping it to a fault status would pass every other test in the suite."""
    from tests.warden.test_app import build, invoke, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    # An OPA that answers with something incoherent: allow=True alongside a
    # non-empty deny_reasons, which pdp.py refuses to trust.
    client, _ = build(
        tmp_path, signer, {"allow": True, "deny_reasons": ["rows.bounded"]}
    )
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    assert response.status_code == 403
    assert response.json()["rule"] == "pdp.unavailable"


def test_authentication_failure_never_reads_the_request_body(tmp_path, monkeypatch):
    """Spine.authenticate() must refuse and the route must return before
    app.py ever awaits the body -- proven directly by spying on
    _parse_args, not just by checking the response, for a missing token, a
    garbage token, and an expired token. This is the exact bug a review
    found: `args = None if credential is None else await _parse_args(...)`
    only skipped the parse for the "no header at all" case -- a
    present-but-invalid credential still reached it, falsifying
    Spine.authenticate()'s own docstring."""
    import warden.broker.app as app_module
    from tests.warden.test_app import Clock, build, token_for
    from warden.broker.identity import Signer

    calls = []
    original_parse_args = app_module._parse_args

    async def spy(request):
        calls.append(1)
        return await original_parse_args(request)

    monkeypatch.setattr(app_module, "_parse_args", spy)

    signer = Signer.generate()
    clock = Clock()
    client, audit = build(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, clock=clock
    )

    # (a) no Authorization header at all.
    client.post("/v1/tools/read_document/invoke", json={"args": {"doc_id": "a"}})
    # (b) a header present, but not a credential the verifier can parse at all.
    client.post(
        "/v1/tools/read_document/invoke",
        json={"args": {"doc_id": "a"}},
        headers={"Authorization": "Bearer not-a-jwt-at-all"},
    )
    # (c) a well-formed, signed token that is simply expired.
    stale = token_for(signer)
    clock.value = 10**12
    client.post(
        "/v1/tools/read_document/invoke",
        json={"args": {"doc_id": "a"}},
        headers={"Authorization": f"Bearer {stale}"},
    )

    assert calls == [], "the body must never be read when authentication fails"
    # The other half of the same risk: one sentinel record per refusal, not
    # two -- the failure mode a route that forgets to stop after rendering
    # an Outcome would produce (authenticate() writes one, then
    # handle_tool_call runs anyway and writes a second for the same
    # refusal).
    records = audit.records()
    assert len(records) == 3
    assert [r["rule"] for r in records] == ["unauthenticated"] * 3


def test_listing_is_filtered_by_the_token_and_records_nothing(tmp_path):
    from tests.warden.test_app import build, token_for
    from warden.broker.identity import Signer
    from warden.broker.spine import Kind

    signer = Signer.generate()
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    spine = client.app.state.spine

    # The token grants three of the catalog's four tools.
    outcome = spine.list_tools(token_for(signer))
    assert outcome.kind is Kind.LISTED
    assert outcome.tools == ("http_fetch", "query_customers", "read_document")
    assert audit.records() == []


def test_an_unauthenticated_listing_is_refused_and_recorded(tmp_path):
    from tests.warden.test_app import build
    from warden.broker.identity import Signer
    from warden.broker.spine import Kind

    signer = Signer.generate()
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    spine = client.app.state.spine

    outcome = spine.list_tools(None)
    assert outcome.kind is Kind.UNAUTHENTICATED
    assert outcome.tools == ()
    records = audit.records()
    assert len(records) == 1
    assert records[0]["action"] == {"type": "tool_list"}
    assert records[0]["agent_id"] == "unauthenticated"
    assert records[0]["rule"] == "unauthenticated"


def test_replay_renders_a_list_refusal(tmp_path):
    """A record shape the renderer has never seen prints as `?()` -- an
    illegible line in the same hash chain as real decisions."""
    from warden.cli.replay import _describe

    rendered = _describe({
        "action": {"type": "tool_list"},
        "target": {"kind": "unknown"},
    })
    assert rendered == "list_tools()"
