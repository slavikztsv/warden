"""The spine's contract: every variant reachable, rendering pure."""

from __future__ import annotations

import pytest

from warden.broker.app import _render
from warden.broker.spine import (
    AUDIT_UNAVAILABLE,
    DENIED,
    FAULT,
    Kind,
    Outcome,
)


def test_every_kind_has_an_http_rendering():
    """Totality. A Kind nobody rendered is a variant that 500s in production."""
    unrenderable = []
    for kind in Kind:
        if kind is Kind.LISTED:
            continue  # ListOutcome, not Outcome -- rendered by list surfaces
        outcome = Outcome(kind=kind, rule="r", message="m")
        if kind is Kind.EXECUTED:
            continue  # covered by test_app.py, needs a real ToolResult
        try:
            _render(outcome)
        except ValueError:
            unrenderable.append(kind)
    assert unrenderable == []


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
    from tests.warden.test_app import Clock, build, invoke, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    spine = client.app.state.spine

    token = token_for(signer)
    outcome = spine.handle_tool_call(token, "read_document", {"doc_id": "a"})

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
    import httpx

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
