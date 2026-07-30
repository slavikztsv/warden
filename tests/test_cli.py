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
    # The verdict is now an argument: render_replay renders what verification
    # found, it does not assert integrity on its own (see
    # test_replay_of_a_tampered_log_is_reported_as_broken).
    assert "chain intact: 3 records" in render_replay(
        [r for r in RECORDS if r["task_id"] == "4711"], chain_ok=True
    )


def test_replay_command_exits_zero(tmp_path, capsys):
    # Built through the real AuditLog rather than from the hand-hashed
    # RECORDS fixture: replay now exits 1 on a broken chain, and those
    # fixtures ("a"*64, "b"*64, ...) never formed a real chain, so replaying
    # them is by definition replaying a tampered log. The assertion this test
    # was always making -- a normal replay exits zero -- needs a valid input
    # to make it against.
    from broker.audit import AuditLog

    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for doc_id in ("ticket-4711", "kb/refund-policy"):
        log.append(
            task_id="4711", agent_id="triage-bot", purpose="support-triage",
            action={"type": "tool_call", "tool": "read_document"},
            target={"kind": "doc", "path": doc_id}, args_digest="sha256:none",
            decision="allow", rule="allow",
            task_state={"data_classes_held": [], "rows_returned_so_far": 0},
            policy_bundle_digest="sha256:demo",
        )
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
    output = render_replay([RECORDS[0]], chain_ok=True)
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


def test_taint_marker_appears_before_the_first_record_that_already_holds_pii():
    # task_state is the snapshot taken BEFORE the record's own call ran (see
    # broker/app.py: `state = taint.snapshot(...)` happens before `decide`,
    # before `execute`, before `record_read`). So the first record whose
    # task_state carries "pii" is the one that *followed* the read that
    # caused it — the marker belongs directly above that record's own line,
    # not below it.
    output = render_replay([r for r in RECORDS if r["task_id"] == "4711"])
    lines = output.splitlines()
    doc_line = next(i for i, l in enumerate(lines) if "read_document" in l)
    query_line = next(i for i, l in enumerate(lines) if "query_customers" in l)
    taint_lines = [i for i, l in enumerate(lines) if "TAINT" in l]
    assert taint_lines == [doc_line + 1] == [query_line - 1]


def test_describe_shows_the_document_id_for_doc_reads():
    record = {
        "task_id": "4711", "agent_id": "triage-bot", "purpose": "support-triage",
        "action": {"type": "tool_call", "tool": "read_document"},
        "target": {"kind": "doc", "path": "kb/refund-policy"},
        "decision": "allow", "rule": "allow",
        "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}, "hash": "0" * 64,
    }
    assert "read_document(kb/refund-policy)" in render_replay([record])


def test_describe_shows_the_recipient_for_mail():
    record = {
        "task_id": "4711", "agent_id": "triage-bot", "purpose": "support-triage",
        "action": {"type": "tool_call", "tool": "send_email"},
        "target": {"kind": "mail", "recipients": ["customer:8812"]},
        "decision": "allow", "rule": "allow",
        "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 1}, "hash": "1" * 64,
    }
    assert "send_email(customer:8812)" in render_replay([record])


# --- The real demo sequence -------------------------------------------------
#
# Eight records for task 4711, built through the actual AuditLog and
# TaintTracker (not hand-rolled dicts), so every hash link and every
# task_state snapshot is exactly what the real broker and proxy would
# produce. Mirrors agent/cassettes/support-triage.json — the ticket read,
# the poisoned kb article, the targeted customer lookup, the blocked bulk
# export, the blocked direct exfil, the blocked fallback to the allowlisted
# but pii-tainted docstore endpoint, and the final legitimate reply — plus
# one record the cassette alone never produces: a raw CONNECT attempt at the
# proxy, showing that layer's independent enforcement on the same task.


def _build_demo_records(path) -> list[dict]:
    from broker.audit import AuditLog
    from broker.taint import TaintTracker

    log = AuditLog(path)
    taint = TaintTracker()
    common = dict(
        task_id="4711", agent_id="triage-bot", purpose="support-triage",
        policy_bundle_digest="sha256:demo",
    )

    def tool_call(tool, target, decision, rule, data_class=None, rows=0):
        state = taint.snapshot("4711")
        log.append(
            action={"type": "tool_call", "tool": tool}, target=target,
            args_digest="sha256:none", decision=decision, rule=rule,
            task_state=state, **common,
        )
        if decision == "allow":
            taint.record_read("4711", data_class=data_class, rows=rows)

    def connect(target, decision, rule):
        # authorize_connect() snapshots and audits but never calls
        # record_read: a tunnel authorization doesn't itself consume or
        # return data, so it cannot taint the task.
        state = taint.snapshot("4711")
        log.append(
            action={"type": "egress", "tool": "CONNECT"}, target=target,
            args_digest="sha256:none", decision=decision, rule=rule,
            task_state=state, **common,
        )

    doc_target = lambda path: {  # noqa: E731
        "kind": "doc", "host": "", "port": 0, "path": path,
        "estimated_rows": 0, "recipients": [],
    }
    db_target = lambda rows: {  # noqa: E731
        "kind": "db", "host": "", "port": 0, "path": "",
        "estimated_rows": rows, "recipients": [],
    }
    http_target = lambda host, port, path: {  # noqa: E731
        "kind": "http", "host": host, "port": port, "path": path,
        "estimated_rows": 0, "recipients": [],
    }
    mail_target = lambda recipients: {  # noqa: E731
        "kind": "mail", "host": "", "port": 0, "path": "",
        "estimated_rows": 0, "recipients": recipients,
    }

    tool_call("read_document", doc_target("ticket-4711"), "allow", "allow",
              data_class="public", rows=0)
    tool_call("read_document", doc_target("kb/refund-policy"), "allow", "allow",
              data_class="public", rows=0)
    tool_call("query_customers", db_target(1), "allow", "allow",
              data_class="pii", rows=1)
    tool_call("query_customers", db_target(10312), "deny", "rows.bounded")
    tool_call("http_fetch", http_target("attacker.example", 80, "/collect"),
               "deny", "egress.allowlist")
    connect(http_target("attacker.example", 443, ""), "deny", "egress.allowlist")
    tool_call("http_fetch", http_target("docstore.internal", 80, "/feedback"),
               "deny", "egress.pii_sink")
    tool_call("send_email", mail_target(["customer:8812"]), "allow", "allow",
              data_class=None, rows=0)

    return log.records()


def test_the_full_demo_sequence_tells_the_right_story(tmp_path):
    from broker.audit import AuditLog

    path = tmp_path / "demo.jsonl"
    records = _build_demo_records(path)
    assert len(records) == 8
    # These records were produced by the real AuditLog, so the chain verdict
    # is computed, not asserted: the "chain intact" line below is now backed
    # by an actual verify_chain() over the actual file.
    chain_ok, bad_seq = AuditLog(path).verify_chain()
    assert (chain_ok, bad_seq) == (True, None)
    output = render_replay(records, chain_ok=chain_ok, bad_seq=bad_seq)
    lines = output.splitlines()

    # The taint marker sits directly under the 1-row lookup that caused it,
    # not under the blocked bulk query that follows it.
    causing_idx = next(i for i, l in enumerate(lines) if "rows≈1)" in l)
    next_idx = next(i for i, l in enumerate(lines) if "rows≈10312)" in l)
    taint_idxs = [i for i, l in enumerate(lines) if "TAINT" in l]
    assert taint_idxs == [causing_idx + 1] == [next_idx - 1]

    # Both the tool-layer and the proxy-layer exfil attempts to the same
    # disallowed host are visible and both denied.
    assert output.count("attacker.example") == 2
    assert output.count("✗") >= 4
    assert "egress.pii_sink" in output
    assert "read_document(ticket-4711)" in output
    assert "read_document(kb/refund-policy)" in output
    assert "send_email(customer:8812)" in output
    assert "chain intact: 8 records" in output


def test_taint_marker_is_between_the_causing_record_and_the_next(tmp_path):
    records = _build_demo_records(tmp_path / "demo.jsonl")
    output = render_replay(records)
    lines = output.splitlines()
    causing_idx = next(i for i, l in enumerate(lines) if "rows≈1)" in l)
    next_idx = next(i for i, l in enumerate(lines) if "rows≈10312)" in l)
    taint_idxs = [i for i, l in enumerate(lines) if "TAINT" in l]
    assert len(taint_idxs) == 1
    assert taint_idxs[0] == causing_idx + 1
    assert taint_idxs[0] == next_idx - 1


# --- The chain claim must be earned, not printed ---------------------------
#
# `chain intact: N records` used to be emitted unconditionally: replay never
# called verify_chain() at all. Flipping a deny to an allow in the log and
# replaying it printed the tampered record under "chain intact" -- the
# artifact asserting the one property it never verified, on the one screen
# whose whole purpose is being trusted.


def _tampered_log(path) -> None:
    """A real chained log with one decision flipped from deny to allow --
    exactly the edit someone hiding a blocked exfil attempt would make."""
    import json

    from broker.audit import AuditLog

    log = AuditLog(path)
    common = dict(
        task_id="4711", agent_id="triage-bot", purpose="support-triage",
        args_digest="sha256:none",
        task_state={"data_classes_held": ["pii"], "rows_returned_so_far": 1},
        policy_bundle_digest="sha256:demo",
    )
    log.append(
        action={"type": "tool_call", "tool": "read_document"},
        target={"kind": "doc", "path": "ticket-4711"},
        decision="allow", rule="allow", **common,
    )
    log.append(
        action={"type": "tool_call", "tool": "http_fetch"},
        target={"kind": "http", "host": "attacker.example", "path": "/collect"},
        decision="deny", rule="egress.allowlist", **common,
    )

    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["decision"] = "allow"
    record["rule"] = "allow"
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")


def test_replay_of_a_tampered_log_is_reported_as_broken(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    _tampered_log(path)

    # Exit 1, not just a banner. `warden replay 4711 && ...` must not succeed
    # over a tampered log, and scripts/demo.sh runs this line under
    # `set -euo pipefail` -- a demo that completes cheerfully over a modified
    # audit chain is worse than one that stops.
    assert main(["replay", "4711", "--audit", str(path)]) == 1
    out = capsys.readouterr().out

    assert "CHAIN BROKEN" in out
    assert "chain intact" not in out
    assert "seq 2" in out  # names the record the tamper was detected at
    assert "nothing above can be trusted" in out
    # The forged line is still shown -- suppressing it would hide the evidence
    # -- but it is shown under a banner that says not to believe it.
    assert "attacker.example" in out


def test_replay_of_an_intact_log_reports_the_chain_as_intact(tmp_path, capsys):
    """Positive control: the banner above must be caused by the tamper, not
    by replay now calling everything broken."""
    from broker.audit import AuditLog

    path = tmp_path / "audit.jsonl"
    AuditLog(path).append(
        task_id="4711", agent_id="triage-bot", purpose="support-triage",
        action={"type": "tool_call", "tool": "read_document"},
        target={"kind": "doc", "path": "ticket-4711"}, args_digest="sha256:none",
        decision="allow", rule="allow",
        task_state={"data_classes_held": [], "rows_returned_so_far": 0},
        policy_bundle_digest="sha256:demo",
    )

    assert main(["replay", "4711", "--audit", str(path)]) == 0
    out = capsys.readouterr().out

    assert "chain intact: 1 records" in out
    assert "BROKEN" not in out


def test_replay_of_a_malformed_record_is_reported_as_broken(tmp_path, capsys):
    """A record missing the fields verify_chain() hashes over (truncated,
    hand-edited) must render as broken rather than crash the CLI."""
    import json

    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps(
            {
                "seq": 1, "task_id": "4711", "agent_id": "triage-bot",
                "purpose": "support-triage",
                "action": {"type": "tool_call", "tool": "read_document"},
                "target": {"kind": "doc", "path": "x"}, "decision": "allow",
                "rule": "allow",
                "task_state": {"data_classes_held": [], "rows_returned_so_far": 0},
                "hash": "0" * 64,  # no prev_hash: verify_chain() raises KeyError
            }
        )
        + "\n"
    )

    assert main(["replay", "4711", "--audit", str(path)]) == 1
    out = capsys.readouterr().out

    assert "CHAIN BROKEN" in out
    assert "chain intact" not in out


def test_the_renderer_never_claims_integrity_it_was_not_given():
    """The default is "not verified", not "intact". A caller that forgets to
    verify says so instead of making the claim for free -- which is exactly
    how the original defect got in."""
    output = render_replay([RECORDS[0]])
    assert "chain NOT VERIFIED" in output
    assert "chain intact" not in output


def test_replay_exit_code_follows_the_chain_verdict(tmp_path, capsys):
    """The banner alone is not the whole answer. `warden replay 4711 && ...`
    must not succeed over a tampered log, and scripts/demo.sh runs exactly
    that line under `set -euo pipefail` -- a demo that completes cheerfully
    over a modified audit chain is worse than one that stops. Both halves
    asserted together, because the pair is the contract: verify-chain already
    exits 1, and replay shrugging would read as an oversight."""
    from broker.audit import AuditLog

    intact = tmp_path / "intact.jsonl"
    AuditLog(intact).append(
        task_id="4711", agent_id="triage-bot", purpose="support-triage",
        action={"type": "tool_call", "tool": "read_document"},
        target={"kind": "doc", "path": "ticket-4711"}, args_digest="sha256:none",
        decision="allow", rule="allow",
        task_state={"data_classes_held": [], "rows_returned_so_far": 0},
        policy_bundle_digest="sha256:demo",
    )
    tampered = tmp_path / "tampered.jsonl"
    _tampered_log(tampered)

    assert main(["replay", "4711", "--audit", str(intact)]) == 0
    assert main(["replay", "4711", "--audit", str(tampered)]) == 1
    out = capsys.readouterr().out
    assert "chain intact" in out
    assert "CHAIN BROKEN" in out


# --- cli.explain --task ----------------------------------------------------
#
# The alternative scenarios ask the operator's instruction to request an
# out-of-scope action directly, instead of relying on the model to follow an
# injected one. They only mean anything with a live model, and getting that
# wrong would let a run misrepresent its own cause.
def test_run_task_uses_the_supplied_instruction():
    """The task text is a parameter, not a constant.

    An out-of-scope request can arrive by injection, by bug, or because the
    operator asked for too much; the loop must be able to express all three.
    """
    import pytest

    from agent.loop import SYSTEM_TASK, run_task

    seen = []

    class Recording:
        def next_step(self, messages):
            seen.append(messages[0]["content"])
            return {"type": "final", "text": "done"}

    run_task(object(), Recording(), task_id="4711", task="do something specific")
    run_task(object(), Recording(), task_id="4711")
    assert seen == ["do something specific", SYSTEM_TASK]


def test_explain_rejects_an_unknown_task_name():
    import pytest

    from cli.explain import _pick_task

    with pytest.raises(SystemExit) as excinfo:
        _pick_task(["--task", "nonsense"], live=True)
    assert "nonsense" in str(excinfo.value)


def test_explain_refuses_an_alternative_task_without_a_live_model():
    """The cassette never reads the prompt.

    Replaying fixed model output under a different instruction would show steps
    the instruction had no part in causing — a demo that lies about itself.
    """
    import pytest

    from cli.explain import TASKS, _pick_task

    for name in TASKS:
        if name == "triage":
            assert _pick_task(["--task", name], live=False)[0] == name
            continue
        with pytest.raises(SystemExit):
            _pick_task(["--task", name], live=False)
        assert _pick_task([f"--task={name}"], live=True)[0] == name
