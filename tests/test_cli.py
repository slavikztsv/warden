from cli.warden import main, render_replay

RECORDS = [
    {"seq": 1, "task_id": "4711", "agent_id": "triage-bot", "purpose": "support-triage",
     "action": {"type": "tool_call", "tool": "read_document"},
     "target": {"kind": "doc"}, "decision": "allow", "rule": "tools.allowed",
     "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}, "hash": "a" * 64},
    {"seq": 2, "task_id": "4711", "agent_id": "triage-bot", "purpose": "support-triage",
     "action": {"type": "tool_call", "tool": "query_customers"},
     "target": {"kind": "db", "estimated_rows": 1}, "decision": "allow", "rule": "rows.bounded",
     "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 1}, "hash": "b" * 64},
    {"seq": 3, "task_id": "4711", "agent_id": "triage-bot", "purpose": "support-triage",
     "action": {"type": "tool_call", "tool": "http_fetch"},
     "target": {"kind": "http", "host": "docstore.internal", "path": "/feedback"},
     "decision": "deny", "rule": "egress.pii_sink",
     "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 1}, "hash": "c" * 64},
    {"seq": 4, "task_id": "9999", "agent_id": "other-bot", "purpose": "other",
     "action": {"type": "tool_call", "tool": "read_document"}, "target": {"kind": "doc"},
     "decision": "allow", "rule": "tools.allowed",
     "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}, "hash": "d" * 64},
]

# A successful CONNECT (the proxy's own record shape: broker/proxy.py's
# authorize_connect) for the same task, once it already holds pii.
CONNECT_RECORD = {
    "seq": 5, "task_id": "4711", "agent_id": "triage-bot", "purpose": "support-triage",
    "action": {"type": "egress", "tool": "CONNECT"},
    "target": {"kind": "http", "host": "docstore.internal", "port": 443, "path": "",
               "estimated_rows": 0, "recipients": []},
    "decision": "allow", "rule": "egress.allowlist",
    "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 1}, "hash": "e" * 64,
}

# A proxy refusal with no valid token: sentinel principal fields per
# broker/proxy.py's _audit_refusal / authorize_connect TokenInvalid path.
SENTINEL_RECORD = {
    "seq": 6, "task_id": "-", "agent_id": "unauthenticated", "purpose": "-",
    "action": {"type": "egress", "tool": "CONNECT"},
    "target": {"kind": "http", "host": "evil.example", "port": 443, "path": "",
               "estimated_rows": 0, "recipients": []},
    "decision": "deny", "rule": "unauthenticated",
    "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}, "hash": "f" * 64,
}


def test_header_names_the_task_and_purpose():
    assert "task 4711" in render_replay(RECORDS)
    assert "purpose=support-triage" in render_replay(RECORDS)


def test_allows_and_denies_are_marked_differently():
    output = render_replay(RECORDS)
    assert "✓ read_document" in output
    assert "✗ http_fetch" in output


def test_the_denying_rule_is_shown():
    assert "egress.pii_sink" in render_replay(RECORDS)


def test_the_taint_transition_is_called_out():
    assert "TAINT" in render_replay(RECORDS)


def test_only_the_requested_task_is_rendered():
    output = render_replay([r for r in RECORDS if r["task_id"] == "4711"])
    assert "other-bot" not in output


def test_chain_head_is_reported():
    assert "chain intact: 3 records" in render_replay(
        [r for r in RECORDS if r["task_id"] == "4711"]
    )


def test_replay_command_exits_zero(tmp_path, capsys):
    import json

    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in RECORDS) + "\n")
    assert main(["replay", "4711", "--audit", str(path)]) == 0
    assert "task 4711" in capsys.readouterr().out


def test_verify_chain_command_reports_tampering(tmp_path, capsys):
    import json

    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in RECORDS) + "\n")
    assert main(["verify-chain", "--audit", str(path)]) == 1
    assert "BROKEN" in capsys.readouterr().out


# --- Edge cases beyond the brief's fixtures: two-producer audit log --------
#
# The audit log holds records from both the broker (tool_call actions) and
# the proxy (egress/CONNECT actions, some with sentinel principal fields
# because no valid token existed to attribute them to). The renderer must
# not choke on either.


def test_render_replay_handles_empty_list():
    assert render_replay([]) == "no records for that task\n"


def test_render_replay_handles_a_single_record():
    output = render_replay([RECORDS[0]])
    assert "task 4711" in output
    assert "chain intact: 1 records" in output


def test_render_replay_handles_connect_and_sentinel_records_without_raising():
    # Order matters for the taint assertion below: pii is already held by
    # the time CONNECT appears, and the sentinel refusal never touches it.
    mixed = [RECORDS[0], RECORDS[1], CONNECT_RECORD, SENTINEL_RECORD]
    output = render_replay(mixed)  # must not raise
    assert "✓ CONNECT" in output
    assert "egress.allowlist" in output
    assert "✗ CONNECT" in output
    assert "unauthenticated" in output


def test_verify_chain_exits_zero_on_an_intact_chain(tmp_path, capsys):
    import json

    path = tmp_path / "audit.jsonl"
    intact = [r for r in RECORDS if r["task_id"] == "4711"][:1]
    path.write_text(json.dumps(intact[0]) + "\n")
    # This fixture record's hash/prev_hash don't form a real chain (the
    # brief's fixtures hardcode "a"*64 etc.), so use AuditLog itself to
    # produce a genuinely intact chain instead of hand-rolled hashes.
    from broker.audit import AuditLog

    log_path = tmp_path / "real_audit.jsonl"
    log = AuditLog(log_path)
    log.append(
        task_id="4711", agent_id="triage-bot", purpose="support-triage",
        action={"type": "tool_call", "tool": "read_document"}, target={"kind": "doc"},
        args_digest="sha256:none", decision="allow", rule="tools.allowed",
        task_state={"data_classes_held": [], "rows_returned_so_far": 0},
        policy_bundle_digest="sha256:none",
    )
    assert main(["verify-chain", "--audit", str(log_path)]) == 0
    out = capsys.readouterr().out
    assert "chain intact" in out
    assert "BROKEN" not in out


def test_verify_chain_exits_nonzero_on_a_missing_file(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.jsonl"
    result = main(["verify-chain", "--audit", str(missing)])
    assert result != 0
    captured = capsys.readouterr()
    assert "BROKEN" not in captured.out  # not mistaken for a tamper report
    assert "chain intact" not in captured.out  # and never reported as passing


def test_verify_chain_on_an_empty_but_present_file(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    assert main(["verify-chain", "--audit", str(path)]) == 0
    assert "chain intact: 0 records" in capsys.readouterr().out


def test_replay_with_no_matching_records_gives_a_clear_message(tmp_path, capsys):
    import json

    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in RECORDS) + "\n")
    result = main(["replay", "no-such-task", "--audit", str(path)])
    out = capsys.readouterr().out
    assert result == 0
    assert "no-such-task" in out
    assert "task 4711" not in out


def test_taint_marker_fires_exactly_once_right_after_the_causing_record():
    output = render_replay([r for r in RECORDS if r["task_id"] == "4711"])
    lines = output.splitlines()
    query_line = next(i for i, l in enumerate(lines) if "query_customers" in l)
    taint_lines = [i for i, l in enumerate(lines) if "TAINT" in l]
    assert taint_lines == [query_line + 1]
