import httpx
import pytest

from broker.audit import AuditLog
from broker.identity import Signer, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.proxy import authorize_connect, parse_authority
from broker.taint import TaintTracker


@pytest.fixture
def signer():
    return Signer.generate()


def deps(tmp_path, opa_payload):
    def handler(request):
        return httpx.Response(200, json={"result": opa_payload})

    return {
        "pdp": PolicyDecisionPoint(
            "http://opa:8181", client=httpx.Client(transport=httpx.MockTransport(handler))
        ),
        "taint": TaintTracker(),
        "audit": AuditLog(tmp_path / "audit.jsonl"),
        "policy_digest": "sha256:test",
    }


def token(signer):
    return signer.mint(
        agent_id="triage-bot",
        task_id="4711",
        purpose="support-triage",
        allowed_tools=["http_fetch"],
        data_classes=["public"],
        counterparties=[],
    )


def test_parse_authority_splits_host_and_port():
    assert parse_authority("attacker.example:443") == ("attacker.example", 443)


def test_parse_authority_defaults_to_443():
    assert parse_authority("attacker.example") == ("attacker.example", 443)


def test_disallowed_destination_is_refused(tmp_path, signer):
    allowed, rule = authorize_connect(
        authority="attacker.example:443",
        token_str=token(signer),
        verifier=Verifier(signer.public_key_pem()),
        **deps(tmp_path, {"allow": False, "deny_reasons": ["egress.allowlist"]}),
    )
    assert (allowed, rule) == (False, "egress.allowlist")


def test_allowed_destination_is_permitted(tmp_path, signer):
    allowed, rule = authorize_connect(
        authority="api.anthropic.com:443",
        token_str=token(signer),
        verifier=Verifier(signer.public_key_pem()),
        **deps(tmp_path, {"allow": True, "deny_reasons": []}),
    )
    assert allowed is True


def test_a_missing_token_is_refused(tmp_path, signer):
    allowed, rule = authorize_connect(
        authority="api.anthropic.com:443",
        token_str="",
        verifier=Verifier(signer.public_key_pem()),
        **deps(tmp_path, {"allow": True, "deny_reasons": []}),
    )
    assert (allowed, rule) == (False, "unauthenticated")


def test_every_connect_decision_is_audited(tmp_path, signer):
    dependencies = deps(tmp_path, {"allow": False, "deny_reasons": ["egress.allowlist"]})
    authorize_connect(
        authority="attacker.example:443",
        token_str=token(signer),
        verifier=Verifier(signer.public_key_pem()),
        **dependencies,
    )
    record = dependencies["audit"].records()[-1]
    assert record["action"] == {"type": "egress", "tool": "CONNECT"}
    assert record["target"]["host"] == "attacker.example"
    assert record["decision"] == "deny"
