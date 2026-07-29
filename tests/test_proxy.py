import httpx
import pytest

from broker.audit import AuditLog
from broker.identity import Signer, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.proxy import _audit_refusal, authorize_connect, parse_authority
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


# A CONNECT with no valid token is what a bypass attempt looks like. If it
# leaves no trace, the proxy has failed at the one job it exists to do.
def test_an_unauthenticated_attempt_is_still_audited(tmp_path, signer):
    dependencies = deps(tmp_path, {"allow": True, "deny_reasons": []})
    authorize_connect(
        authority="attacker.example:443",
        token_str="",
        verifier=Verifier(signer.public_key_pem()),
        **dependencies,
    )
    record = dependencies["audit"].records()[-1]
    assert record["decision"] == "deny"
    assert record["rule"] == "unauthenticated"
    assert record["agent_id"] == "unauthenticated"
    assert record["target"]["host"] == "attacker.example"
    assert record["action"] == {"type": "egress", "tool": "CONNECT"}


def test_parse_authority_never_raises_on_hostile_input(tmp_path):
    assert parse_authority("[::1]:443") == ("::1", 443)
    assert parse_authority("host:notanumber")[1] == 0
    assert parse_authority("a:b:c")[1] == 0
    assert parse_authority("") == ("", 443)
    # A leading colon must not be mistaken for "no port present".
    assert parse_authority(":8080") == ("", 8080)


# An oversized header raises inside asyncio's reader BEFORE authorization is
# reached. It must still refuse with a response and leave a record — a bare
# socket close would make a probe look like it never happened.
def test_an_unparseable_request_is_refused_and_recorded(tmp_path, signer):
    dependencies = deps(tmp_path, {"allow": True, "deny_reasons": []})
    _audit_refusal(
        audit=dependencies["audit"],
        policy_digest=dependencies["policy_digest"],
        host="",
        port=0,
        rule="proxy.unparseable",
    )
    record = dependencies["audit"].records()[-1]
    assert record["decision"] == "deny"
    assert record["rule"] == "proxy.unparseable"
    assert record["action"] == {"type": "egress", "tool": "CONNECT"}
    assert dependencies["audit"].verify_chain() == (True, None)


def test_a_non_connect_method_is_recorded(tmp_path, signer):
    dependencies = deps(tmp_path, {"allow": True, "deny_reasons": []})
    _audit_refusal(
        audit=dependencies["audit"],
        policy_digest=dependencies["policy_digest"],
        host="attacker.example",
        port=443,
        rule="proxy.method_not_allowed",
    )
    record = dependencies["audit"].records()[-1]
    assert record["rule"] == "proxy.method_not_allowed"
    assert record["target"]["host"] == "attacker.example"


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
