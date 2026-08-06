"""B7: the control plane records what it grants.

Every test here is a row in the B7 design's proof table
(docs/superpowers/specs/2026-08-06-p2b7-audit-the-mint-design.md), and every
one was made to fail before it was allowed to count.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from warden.broker.audit import AuditLog
from warden.broker.control import MINT_UNAVAILABLE_MESSAGE, create_control_app
from warden.broker.identity import ISSUER, Signer, Verifier
from warden.broker.record_fields import args_digest, empty_task_state

GRANT = {
    "agent_id": "triage-bot",
    "task_id": "4711",
    "purpose": "support-triage",
    "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "data_classes": ["public", "pii"],
    "counterparties": ["customer:8812"],
}


def control(tmp_path, *, issuer=ISSUER, signer=None, audit=None):
    signer = signer or Signer.generate(issuer=issuer)
    audit = audit if audit is not None else AuditLog(tmp_path / "audit.jsonl")
    app = create_control_app(signer=signer, audit=audit, issuer=issuer)
    return TestClient(app), signer, audit


def decision(log, **overrides):
    """A broker-shaped tool_call record, so a mint can be tested among them."""
    fields = dict(
        task_id="4711", agent_id="triage-bot", purpose="support-triage",
        action={"type": "tool_call", "tool": "read_document"},
        target={"kind": "doc", "path": "kb/refund-policy"},
        args_digest="sha256:aaa", decision="allow", rule="allow",
        task_state={"data_classes_held": [], "rows_charged_so_far": 0},
        policy_bundle_digest="sha256:bbb",
    )
    fields.update(overrides)
    return log.append(**fields)


# --- row 1: the field set is the record shape, unchanged ---------------------


def test_a_mint_record_has_the_same_fields_as_a_decision(tmp_path):
    """The whole reason the grant goes in `target` rather than in a fourteenth
    body field.

    The record body is one of the three interfaces ROADMAP F3 says other
    people depend on, and test_a_written_record_has_exactly_these_fields
    exists so growing it is a deliberate act. B7 does not grow it: the mint
    reuses all thirteen, with two honest sentinels, so AuditLog's interface is
    untouched and the demo's NarratedAudit cannot rot against it.
    """
    client, _, audit = control(tmp_path)
    assert client.post("/v1/tokens", json=GRANT).status_code == 200

    mint = audit.records()[0]
    tool_call = decision(audit)
    assert sorted(mint) == sorted(tool_call)
    # And on DISK, not just what append() returned -- they are different dicts
    # and only one of them is the artifact anybody audits.
    written = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert sorted(written) == sorted(mint)


# --- row 2: it chains --------------------------------------------------------


def test_a_mint_record_chains_with_the_decisions_after_it(tmp_path):
    client, _, audit = control(tmp_path)
    client.post("/v1/tokens", json=GRANT)
    decision(audit)
    decision(audit, decision="deny", rule="rows.bounded")

    records = audit.records()
    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[0]["prev_hash"] == "0" * 64
    assert records[1]["prev_hash"] == records[0]["hash"]
    assert audit.verify_chain() == (True, None)


# --- row 3: the record follows the TOKEN, not the request --------------------


def test_the_recorded_grant_follows_the_token_not_the_request(tmp_path, monkeypatch):
    """Why record_mint takes a verified TaskToken instead of the request body.

    The two are byte-identical today, because Signer.mint copies every field
    it is given -- which is exactly why this row needs a divergence
    manufactured to have anything to catch. The first draft of the proof table
    proposed "mint with a TTL the request did not name"; TokenRequest has no
    TTL field, so that is every TTL, and the test would have passed against a
    record built from the request. This is the only construction in which "if
    those two ever diverge" is testable.
    """
    signer = Signer.generate()
    real_mint = signer.mint

    def narrower_mint(**kwargs):
        # A mint() that hands out LESS than was asked for. The record must
        # describe what the broker will enforce, not what the caller wanted.
        kwargs["allowed_tools"] = ["read_document"]
        return real_mint(**kwargs)

    monkeypatch.setattr(signer, "mint", narrower_mint)
    client, _, audit = control(tmp_path, signer=signer)

    assert client.post("/v1/tokens", json=GRANT).status_code == 200
    assert audit.records()[0]["target"]["allowed_tools"] == ["read_document"]
    assert GRANT["allowed_tools"] != ["read_document"]  # the request asked for four


# --- row 4: the exact fields, values and all ---------------------------------


def test_a_mint_record_carries_these_exact_fields(tmp_path):
    """Rows 1 and 2 are insensitive to VALUES: a record whose rule says
    "allow" and whose policy_bundle_digest is a real digest copied from
    somewhere passes both. Only an explicit assertion pins the two sentinels
    and the claim that nothing evaluated this mint.
    """
    client, signer, audit = control(tmp_path)
    raw = client.post("/v1/tokens", json=GRANT).json()["token"]
    token = Verifier(signer.public_key_pem()).verify(raw)

    record = audit.records()[0]
    assert record["action"] == {"type": "mint"}
    assert record["task_id"] == "4711"
    assert record["agent_id"] == "triage-bot"
    assert record["purpose"] == "support-triage"
    assert record["decision"] == "allow"
    # Not "allow": no policy rule fired, and saying "allow" would claim one
    # did. When C2 gives the control plane a policy this becomes a real name.
    assert record["rule"] == "mint.unconditional"
    # Not "sha256:none": the bundle does not exist, it was not merely unread.
    assert record["policy_bundle_digest"] == "none"
    # A REAL digest, unlike the two sentinels around it: there were arguments,
    # and this is what they were. Asserted because a mutation that appended to
    # it left every other assertion in this test green -- the one field the
    # first version of this test forgot.
    assert record["args_digest"] == args_digest(GRANT)
    assert record["task_state"] == {"data_classes_held": [], "rows_charged_so_far": 0}
    assert record["target"] == {
        "kind": "token",
        "allowed_tools": GRANT["allowed_tools"],
        "data_classes": GRANT["data_classes"],
        "counterparties": GRANT["counterparties"],
        "delegated_from": None,
        "jti": token.jti,
        "exp": token.exp,
    }
    # The credential itself is never in the log. warden replay prints what it
    # is given, and a JWT is a bearer credential.
    assert raw not in (tmp_path / "audit.jsonl").read_text()


# --- row 5: a re-mint records the MINTER'S view ------------------------------


def test_a_remint_records_the_minters_empty_view(tmp_path):
    """task_state on a mint is a sentinel, and this pins that it is one.

    Task state is keyed by task_id and deliberately survives token renewal, so
    a renewal minted for a task that has already read rows and holds pii is
    recorded with [] and 0 anyway -- the control plane holds no task-state
    store and cannot say otherwise. The shape is forced by warden/cli/
    replay.py, which subscripts task_state["data_classes_held"] for every
    record. This test exists so a later reader does not mistake the value for
    a measurement.
    """
    client, _, audit = control(tmp_path)
    client.post("/v1/tokens", json=GRANT)
    # A tool call that leaves the task holding pii and 5001 rows charged.
    decision(audit, task_state={"data_classes_held": ["pii"], "rows_charged_so_far": 5001})
    client.post("/v1/tokens", json=GRANT)  # the renewal

    mints = [r for r in audit.records() if r["action"]["type"] == "mint"]
    assert len(mints) == 2
    for mint in mints:
        assert mint["task_state"] == {"data_classes_held": [], "rows_charged_so_far": 0}


# --- rows 6 and 7: it fails closed, without naming the log -------------------


def test_a_mint_that_cannot_be_recorded_returns_503_and_no_token(tmp_path):
    """The spine's rule, applied to the biggest grant in the system.

    proxy.py and the MCP era gate both go the other way, and both justify it
    on two conditions: the outcome is a REFUSAL, and there is no channel to
    report an unavailable log through. A mint satisfies neither.
    """
    client, _, audit = control(tmp_path, audit=AuditLog(tmp_path / "audit.jsonl"))

    def refuse(**fields):
        raise OSError(f"[Errno 28] No space left on device: '{tmp_path / 'audit.jsonl'}'")

    audit.append = refuse  # type: ignore[method-assign]
    response = client.post("/v1/tokens", json=GRANT)

    assert response.status_code == 503
    assert "token" not in response.json()
    assert response.json()["detail"] == MINT_UNAVAILABLE_MESSAGE
    assert audit.records() == []


def test_the_mint_failure_does_not_name_the_audit_log(tmp_path):
    """AuditLog's own OSError names the audit path verbatim -- _acquire's
    message is "audit log <path> is held by another writer". Rendering
    str(exc) to a caller is a defect this repo already had and fixed once on
    the HTTP door, which is why refusals.py exists.
    """
    client, _, audit = control(tmp_path)

    def refuse(**fields):
        raise OSError(f"audit log {tmp_path / 'audit.jsonl'} is held by another writer")

    audit.append = refuse  # type: ignore[method-assign]
    body = client.post("/v1/tokens", json=GRANT).json()

    assert "audit.jsonl" not in body["detail"]
    assert str(tmp_path) not in body["detail"]
    assert "Errno" not in body["detail"]


# --- row 8: a configured issuer still works ----------------------------------


def test_a_configured_issuer_still_mints_and_records(tmp_path):
    """The blocker the design review caught before implementation.

    Signer keeps its issuer private and exposes no accessor, so a Verifier
    built from signer.public_key_pem() alone falls back to identity.py's
    module default. Every deployment naming a different issuer -- which
    tests/warden/test_key_split.py builds and asserts 200 for -- would then
    500 on its first mint, and TokenInvalid is not an OSError so the
    fail-closed handler would not catch it. Measured before the fix: HTTP 500,
    zero records.
    """
    client, _, audit = control(tmp_path, issuer="control-plane-a")
    assert client.post("/v1/tokens", json=GRANT).status_code == 200
    assert len(audit.records()) == 1
    assert audit.records()[0]["action"] == {"type": "mint"}


# --- row 11: the app cannot be built without a log ---------------------------


def test_the_control_app_requires_an_audit_log():
    """No deployment path exists that mints without recording. A config check
    would catch a missing [audit] section; this catches a caller that builds
    the app directly, which is what every test and control_main.build() do.
    """
    signer = Signer.generate()
    with pytest.raises(TypeError, match="audit"):
        create_control_app(signer=signer, issuer=ISSUER)  # type: ignore[call-arg]


# --- row 12: two processes, one chain ----------------------------------------


_MINT_SCRIPT = """
import sys
from warden.broker.audit import AuditLog
from warden.broker.control import record_mint
from warden.broker.identity import Signer, Verifier

signer = Signer.generate()
verifier = Verifier(signer.public_key_pem())
log = AuditLog(sys.argv[1])
for _ in range(int(sys.argv[2])):
    raw = signer.mint(
        agent_id="triage-bot", task_id="4711", purpose="support-triage",
        allowed_tools=["read_document"], data_classes=["public"],
        counterparties=["customer:8812"],
    )
    record_mint(log, token=verifier.verify(raw), request_digest="sha256:ccc")
"""

_DECIDE_SCRIPT = """
import sys
from warden.broker.audit import AuditLog

log = AuditLog(sys.argv[1])
for _ in range(int(sys.argv[2])):
    log.append(
        task_id="4711", agent_id="triage-bot", purpose="support-triage",
        action={"type": "tool_call", "tool": "read_document"},
        target={"kind": "doc"}, args_digest="sha256:aaa",
        decision="allow", rule="allow",
        task_state={"data_classes_held": [], "rows_charged_so_far": 0},
        policy_bundle_digest="sha256:bbb",
    )
"""


def test_a_mint_and_broker_appends_produce_one_intact_chain(tmp_path):
    """The reason B7 needed B6, run as two real processes.

    The mint does not happen in the broker. It happens in a separate service
    that already shares ./data:/data with it, so a mint record in the same log
    is a second writer BY CONSTRUCTION -- and before B6 it would have produced
    the exact corruption B6 removed, in the worst available shape: the control
    plane writes once per task against the broker's constant traffic, so the
    breakage would have been rare, intermittent and indistinguishable from
    tampering.

    A FRESH INTERPRETER, not a fork, and not threads. tests/ has no
    __init__.py and pytest.ini sets --import-mode=importlib, so a spawn child
    cannot re-import a test module; forking a multi-threaded pytest process is
    a documented deadlock hazard; and a thread-based version passes against a
    process-local-lock bug, because the threading.Lock already excludes
    threads.
    """
    path = tmp_path / "audit.jsonl"
    mints, per_writer = 2, 30
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(path), str(per_writer)],
            stderr=subprocess.PIPE,
            text=True,
        )
        # Started before any is waited on, so they genuinely contend.
        for script in ([_MINT_SCRIPT] * mints + [_DECIDE_SCRIPT] * 2)
    ]
    for worker in workers:
        _, stderr = worker.communicate(timeout=120)
        assert worker.returncode == 0, stderr

    log = AuditLog(path)
    records = log.records()
    total = (mints + 2) * per_writer
    assert len(records) == total
    assert [r["seq"] for r in records] == list(range(1, total + 1))
    assert log.verify_chain() == (True, None)
    assert sum(1 for r in records if r["action"]["type"] == "mint") == mints * per_writer


# --- the control.toml the demo ships must name the broker's log --------------


def test_the_shipped_control_toml_names_the_brokers_audit_log(tmp_path):
    """Nothing in the product compares these two strings, so this does.

    compose.yml mounts ./data:/data into both services, which guarantees the
    DIRECTORY. The file is two independently authored, ${VAR}-interpolated
    values in two TOMLs, and a typo produces the separate mint log the B7
    design rejects -- silently, at no boot. Same hazard as [tokens].issuer,
    which has the same must-match comments and its own end-to-end test.
    """
    root = Path(__file__).resolve().parents[2]
    control = (root / "demo" / "scenario" / "control.toml").read_text()
    broker = (root / "demo" / "scenario" / "warden.toml").read_text()

    def audit_path(text: str) -> str:
        section = text.split("[audit]", 1)[1]
        return re.search(r'path\s*=\s*"([^"]+)"', section).group(1)

    assert audit_path(control) == audit_path(broker)


# --- the shared record vocabulary --------------------------------------------


def test_empty_task_state_is_a_fresh_dict_per_call():
    """record_fields.empty_task_state's docstring warns about this, and until
    B7's mutation pass nothing enforced it.

    AuditLog.append does `record = dict(body)` -- a SHALLOW copy -- so a shared
    module-level constant would make every record built from it alias one
    object. Nothing keeps those return values today, which is exactly why the
    hazard is worth a test rather than a comment: the next caller to keep one
    would not know it was holding a landmine, and B7 just added the second
    caller.

    Measured: replacing the dict literal with a module constant left all 832
    tests green.
    """
    first, second = empty_task_state(), empty_task_state()
    assert first == second
    assert first is not second
    assert first["data_classes_held"] is not second["data_classes_held"]

    first["data_classes_held"].append("pii")
    first["rows_charged_so_far"] = 5001
    assert empty_task_state() == {"data_classes_held": [], "rows_charged_so_far": 0}
