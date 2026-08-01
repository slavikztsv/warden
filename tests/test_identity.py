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


# --- issuer and ttl_seconds are configured, not hardcoded -------------------
#
# Task 14 review finding: warden.toml/control.toml parsed [tokens].issuer and
# [tokens].ttl_seconds, but broker/identity.py's ISSUER and
# DEFAULT_TTL_SECONDS module constants were what mint() and verify() actually
# used -- the config was decorative. These prove the configured values are
# the ones that take effect, not the constants.


def test_a_token_minted_under_a_different_configured_issuer_is_rejected():
    """warden.toml's [tokens].issuer and control.toml's [tokens].issuer must
    agree. If an operator (or a deploy mistake) lets them drift, every token
    must fail verification -- loud, total failure, not a silent pass-through
    on the module constant both sides used to share regardless of config."""
    signer = Signer.generate(issuer="control-plane-a")
    verifier = Verifier(signer.public_key_pem(), issuer="control-plane-b")
    token = mint(signer)
    with pytest.raises(TokenInvalid):
        verifier.verify(token, now=1_785_318_010)

    # Positive control: the same signer/verifier pair, configured to AGREE,
    # still verifies -- so the rejection above is really about the mismatch,
    # not some other side effect of passing issuer= at all.
    agreeing_verifier = Verifier(signer.public_key_pem(), issuer="control-plane-a")
    agreeing_verifier.verify(token, now=1_785_318_010)


def test_configured_ttl_seconds_changes_the_minted_tokens_expiry():
    """Asserted against the decoded claim, not the DEFAULT_TTL_SECONDS
    constant: a control.toml with ttl_seconds = 3600 must produce a token
    whose exp is 3600 seconds out, not 300."""
    signer = Signer.generate(default_ttl_seconds=3600)
    verifier = Verifier(signer.public_key_pem())
    token_str = mint(signer, now=1_000_000)
    token = verifier.verify(token_str, now=1_000_000)
    assert token.exp == 1_000_000 + 3600
    assert token.exp != 1_000_000 + 300  # the old, now-wrong default


def test_mint_still_defaults_to_the_module_constant_when_unconfigured():
    """Direct construction (Signer.generate() with no issuer/ttl_seconds) is
    still how tests and cli/explain.py's standalone demo signer work -- the
    module constants are the default, not a value that vanished."""
    from broker.identity import DEFAULT_TTL_SECONDS, ISSUER

    signer = Signer.generate()
    verifier = Verifier(signer.public_key_pem())
    token_str = mint(signer, now=1_000_000)
    token = verifier.verify(token_str, now=1_000_000)
    assert token.exp == 1_000_000 + DEFAULT_TTL_SECONDS
    assert ISSUER == "warden-broker"  # the shared default both sides agree on
