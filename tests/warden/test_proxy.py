import asyncio
import base64
import socket

import httpx
import pytest

from warden.broker.audit import AuditLog
from warden.broker.identity import Signer, Verifier
from warden.broker.pdp import PolicyDecisionPoint
from warden.broker.proxy import (
    _audit_refusal,
    authorize_connect,
    parse_authority,
    proxy_token,
    serve_proxy,
)
from warden.broker.taint import InMemoryTaskStateStore


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
        "task_state": InMemoryTaskStateStore(),
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
    allowed, _rule = authorize_connect(
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


# The open_connection guard and the audit-write guard both live inside
# serve_proxy's closure, not in authorize_connect -- driving a real server
# (loopback only, no external network access) is the only way to exercise
# them. An allow record must never be paired with silence on the wire.
async def test_an_unreachable_upstream_gets_a_response_not_silence(tmp_path, signer):
    dependencies = deps(tmp_path, {"allow": True, "deny_reasons": []})
    server = await serve_proxy(
        "127.0.0.1", 0, verifier=Verifier(signer.public_key_pem()), **dependencies
    )
    try:
        proxy_host, proxy_port = server.sockets[0].getsockname()[:2]

        # Bind then close: guarantees nothing is listening on this port, so
        # the server's own asyncio.open_connection to it fails fast with
        # ConnectionRefusedError -- no DNS lookup, no external network access.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        writer.write(
            f"CONNECT 127.0.0.1:{closed_port} HTTP/1.1\r\n"
            f"Proxy-Authorization: Bearer {token(signer)}\r\n\r\n".encode()
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=5)
        writer.close()

        assert response == (
            b"HTTP/1.1 502 Bad Gateway\r\nX-Warden-Rule: upstream.unreachable\r\n\r\n"
        )
        records = dependencies["audit"].records()
        assert len(records) == 1
        assert records[0]["decision"] == "allow"
    finally:
        server.close()
        await server.wait_closed()


async def test_an_audit_write_failure_during_authorize_connect_is_reported_distinctly(
    tmp_path, signer, monkeypatch
):
    dependencies = deps(tmp_path, {"allow": True, "deny_reasons": []})

    def raise_oserror(**kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(dependencies["audit"], "append", raise_oserror)

    server = await serve_proxy(
        "127.0.0.1", 0, verifier=Verifier(signer.public_key_pem()), **dependencies
    )
    try:
        proxy_host, proxy_port = server.sockets[0].getsockname()[:2]
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        writer.write(
            f"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
            f"Proxy-Authorization: Bearer {token(signer)}\r\n\r\n".encode()
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=5)
        writer.close()

        assert response == (
            b"HTTP/1.1 503 Service Unavailable\r\nX-Warden-Rule: audit.unavailable\r\n\r\n"
        )
    finally:
        server.close()
        await server.wait_closed()


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


# A model SDK owns its own HTTP client and will not set a Bearer header for us.
# Embedding the token in the proxy URL makes every proxy-aware client send it
# as Basic credentials, which is the only way to authenticate a third party's
# internal client without patching it.
def test_proxy_token_accepts_a_bearer_header():
    assert proxy_token("Bearer abc.def.ghi") == "abc.def.ghi"


def test_proxy_token_accepts_basic_credentials_and_ignores_the_username():
    header = "Basic " + base64.b64encode(b"anything:abc.def.ghi").decode()
    assert proxy_token(header) == "abc.def.ghi"


def test_proxy_token_survives_a_password_containing_colons():
    header = "Basic " + base64.b64encode(b"agent:a:b:c").decode()
    assert proxy_token(header) == "a:b:c"


def test_proxy_token_yields_empty_for_anything_it_cannot_parse():
    # Empty means "no token", which fails verification and is audited as
    # unauthenticated — never an exception, never a bypass.
    assert proxy_token("") == ""
    assert proxy_token("Digest xyz") == ""
    assert proxy_token("Basic !!!not-base64!!!") == ""
    assert proxy_token("Basic " + base64.b64encode(b"\xff\xfe").decode()) == ""
