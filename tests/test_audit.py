import json
from pathlib import Path

from broker.audit import GENESIS_HASH, AuditLog, canonical_json


def _append(log, **overrides):
    fields = dict(
        task_id="4711",
        agent_id="triage-bot",
        purpose="support-triage",
        action={"type": "tool_call", "tool": "read_document"},
        target={"kind": "doc"},
        args_digest="sha256:aaa",
        decision="allow",
        rule="tools.allowed",
        task_state={"data_classes_held": [], "rows_returned_so_far": 0},
        policy_bundle_digest="sha256:bbb",
    )
    fields.update(overrides)
    return log.append(**fields)


def test_canonical_json_is_stable_under_key_order(tmp_path):
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_first_record_links_to_genesis(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    record = _append(log)
    assert record["seq"] == 1
    assert record["prev_hash"] == GENESIS_HASH
    assert len(record["hash"]) == 64


def test_each_record_links_to_its_predecessor(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    first = _append(log)
    second = _append(log, decision="deny", rule="egress.pii_sink")
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]


def test_chain_verifies_when_untouched(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _append(log)
    _append(log)
    _append(log)
    assert log.verify_chain() == (True, None)


def test_tampering_with_a_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    _append(log, decision="deny", rule="rows.bounded")
    _append(log)

    lines = path.read_text().splitlines()
    doctored = json.loads(lines[1])
    doctored["decision"] = "allow"
    lines[1] = json.dumps(doctored)
    path.write_text("\n".join(lines) + "\n")

    ok, bad_seq = AuditLog(path).verify_chain()
    assert ok is False
    assert bad_seq == 2


def test_log_reopens_and_continues_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = _append(AuditLog(path))
    second = _append(AuditLog(path))
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]
