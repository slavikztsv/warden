import pytest

from broker.identity import Signer, TokenInvalid, Verifier


@pytest.fixture
def signer():
    return Signer.generate()


@pytest.fixture
def verifier(signer):
    return Verifier(signer.public_key_pem())


def mint(signer, **overrides):
    fields = dict(
        agent_id="triage-bot",
        task_id="4711",
        purpose="support-triage",
        allowed_tools=["read_document", "query_customers", "http_fetch", "send_email"],
        data_classes=["public", "internal"],
        counterparties=["customer:8812"],
        now=1_785_318_000,
    )
    fields.update(overrides)
    return signer.mint(**fields)


def test_round_trip_preserves_claims(signer, verifier):
    token = verifier.verify(mint(signer), now=1_785_318_010)
    assert token.agent_id == "triage-bot"
    assert token.task_id == "4711"
    assert token.purpose == "support-triage"
    assert token.counterparties == ("customer:8812",)
    assert token.delegated_from is None


def test_token_expires_after_five_minutes(signer, verifier):
    token_str = mint(signer)
    verifier.verify(token_str, now=1_785_318_299)
    with pytest.raises(TokenInvalid):
        verifier.verify(token_str, now=1_785_318_301)


def test_tampered_payload_is_rejected(signer, verifier):
    header, payload, signature = mint(signer).split(".")
    other = mint(signer, purpose="admin-everything")
    forged = f"{header}.{other.split('.')[1]}.{signature}"
    with pytest.raises(TokenInvalid):
        verifier.verify(forged, now=1_785_318_010)


def test_a_different_key_cannot_mint_an_acceptable_token(verifier):
    attacker = Signer.generate()
    with pytest.raises(TokenInvalid):
        verifier.verify(mint(attacker), now=1_785_318_010)


def test_garbage_is_rejected_without_raising_a_library_error(verifier):
    with pytest.raises(TokenInvalid):
        verifier.verify("not-a-token", now=1_785_318_010)
