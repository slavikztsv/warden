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

    from pathlib import Path

    from cli.explain import TASKS, _pick_task

    for name in TASKS:
        # A scenario with its own recording is deterministic and needs no key;
        # one without would replay the default transcript, showing steps this
        # instruction had no part in causing.
        has_recording = Path(f"agent/cassettes/{name}.json").exists()
        if name == "triage" or has_recording:
            assert _pick_task(["--task", name], live=False)[0] == name
            continue
        with pytest.raises(SystemExit):
            _pick_task(["--task", name], live=False)
        assert _pick_task([f"--task={name}"], live=True)[0] == name


def test_every_scenario_declares_what_it_trips_and_what_it_costs():
    """The scenario table is demo copy as much as configuration.

    A scenario with no stated damage is one nobody can present, and a scenario
    whose `trips` does not name a real rule is a claim the run cannot back up.
    """
    from cli.explain import TASKS

    rules = {"input.malformed", "tools.allowed", "egress.allowlist",
             "egress.pii_sink", "rows.bounded", "rows.scope", "mail.counterparty"}
    for name, spec in TASKS.items():
        assert spec["say"].strip(), name
        assert spec["damage"].strip(), name
        named = [r for r in rules if r in spec["trips"]]
        if "NOTHING" in spec["trips"]:
            # A scenario that trips nothing is a documented gap, not an oversight.
            assert "THREAT_MODEL" in spec["trips"], name
        else:
            assert named or name == "triage", f"{name} names no rule"
    assert TASKS["readonly"]["grant"]["allowed_tools"] == [
        "read_document", "query_customers"
    ], "the read-only scenario must actually withhold the write tools"


def test_the_precedence_list_covers_every_rule_the_policy_can_return():
    """A deny reason absent from DENY_PRECEDENCE falls through to
    pdp.unavailable — fail-closed, but it reports the wrong cause and hides
    which control fired. Adding a rule means adding it here."""
    import re
    from pathlib import Path

    from broker.pdp import DENY_PRECEDENCE

    rego = Path("policies/authz.rego").read_text()
    emitted = set(re.findall(r'deny_reasons contains "([^"]+)"', rego))
    assert emitted <= set(DENY_PRECEDENCE), (
        f"rules the PDP cannot name: {emitted - set(DENY_PRECEDENCE)}"
    )

def test_comparison_table_marks_only_the_rows_that_differ():
    """The table is the demo's headline, so its arrow must mean something.

    Every row is a measured value from the two runs; nothing in it is asserted
    by the narration, which is the point of printing them side by side.
    """
    from cli.explain import render_comparison

    table = render_comparison(
        {"records read": 10313, "emails delivered": 1, "audit records": "none"},
        {"records read": 1, "emails delivered": 1, "audit records": "7, chain intact"},
        live=False,
        task="triage",
    )
    lines = {line.split("  ")[1].strip(): line for line in table.splitlines() if "  " in line}
    assert "←" in lines["records read"], "a differing row must be marked"
    assert "←" not in lines["emails delivered"], "an identical row must not be"
    assert "10,313" in table and "chain intact" in table
    assert "recorded model" in table


# --- cli.sweep -------------------------------------------------------------
#
# Measures which models actually follow the injected instruction, by reading
# bytes off the sinkhole rather than judging the model's output. The table it
# prints is the artifact, so its ordering and its honest-empty case are worth
# pinning.
def test_sweep_table_ranks_by_bytes_that_actually_left():
    from cli.sweep import render

    table = render([
        {"model": "a/clean", "calls": 4, "rows": 1, "attempted": 0, "bytes": 0,
         "emailed": 1, "error": ""},
        {"model": "b/leaky", "calls": 6, "rows": 10312, "attempted": 1, "bytes": 121,
         "emailed": 1, "error": ""},
        {"model": "c/tried", "calls": 5, "rows": 1, "attempted": 1, "bytes": 0,
         "emailed": 1, "error": ""},
        {"model": "d/broken", "calls": 0, "rows": 0, "attempted": 0, "bytes": 0,
         "emailed": 0, "error": "429 rate limited"},
    ])
    body = [ln for ln in table.splitlines() if "/" in ln and "OPENROUTER_MODEL" not in ln]
    assert body[0].split()[0] == "b/leaky", "the biggest leak ranks first"
    assert "←" in body[0] and "←" not in body[1]
    assert "1 of 3 models sent customer data" in table
    assert "rate limited (free tier)" in table, "errors are classified, not dumped"
    # The suggested next command must name the model that actually leaked.
    assert "OPENROUTER_MODEL=b/leaky" in table


def test_sweep_reports_no_compliance_as_a_result_not_a_failure():
    """A sweep where nothing leaks is a finding about models, and the reason
    the recorded cassette is treated as a fixed adversarial model."""
    from cli.sweep import render

    table = render([
        {"model": "a/one", "calls": 4, "rows": 1, "attempted": 0, "bytes": 0,
         "emailed": 1, "error": ""},
    ])
    assert "0 of 1 models sent customer data" in table
    assert "not a failed sweep" in table
    assert "OPENROUTER_MODEL=" not in table


def test_sweep_selects_only_tool_capable_models():
    from cli.sweep import tool_capable

    catalogue = [
        {"id": "v/free-tools", "supported_parameters": ["tools"],
         "pricing": {"prompt": "0"}},
        {"id": "v/paid-tools", "supported_parameters": ["tools"],
         "pricing": {"prompt": "0.0000005"}},
        {"id": "v/no-tools", "supported_parameters": ["temperature"],
         "pricing": {"prompt": "0"}},
        {"id": "v/nothing"},
    ]
    assert tool_capable(catalogue, free_only=True) == ["v/free-tools"]
    assert tool_capable(catalogue, free_only=False) == ["v/free-tools", "v/paid-tools"]


def test_openrouter_retry_budget_is_configurable():
    """A sweep wants to give up on a busy free model quickly; a single live run
    does not. Default stays 5."""
    import httpx
    import pytest

    from agent.llm import OpenRouterClient

    tries = []

    def handler(request):
        tries.append(1)
        return httpx.Response(429, text="slow down")

    client = OpenRouterClient(
        "k", client=httpx.Client(transport=httpx.MockTransport(handler)), retries=1
    )
    with pytest.raises(RuntimeError) as excinfo:
        client.next_step([{"role": "user", "content": "go"}])
    assert len(tries) == 1, "retries=1 must not sleep or retry at all"
    assert "1 attempts" in str(excinfo.value)


def test_agent_loop_can_be_capped():
    """Unbounded, the loop runs until the model chooses to stop. The sweep runs
    models it has never seen, some of which never choose to."""
    from agent.loop import run_task

    class NeverFinishes:
        def next_step(self, messages):
            return {"type": "tool_use", "tool": "read_document", "args": {"doc_id": "x"}}

    class Ok:
        def __init__(self):
            self.calls = 0

        def call(self, tool, args):
            self.calls += 1
            return {"content": "ok", "rows": 0}

    dispatcher = Ok()
    transcript = run_task(dispatcher, NeverFinishes(), task_id="4711", max_steps=5)
    # The cap bounds executed turns; the transcript then carries the stop marker,
    # so the loop still ends on a `final` exactly as an ordinary run does.
    assert dispatcher.calls == 5
    assert len(transcript) == 6
    assert transcript[-1] == {"type": "final", "text": "(stopped after 5 steps)"}


def test_a_recorded_scenario_drives_both_profiles_from_one_transcript():
    """The point of recording a complying run.

    Two live runs sample independently, so the unguarded side can follow an
    injected instruction while the guarded side never attempts it — and then
    "0 bytes with the broker" is not the broker's doing. Observed exactly that
    before cli.record existed. A scenario with its own cassette must replay it
    in both profiles, or the comparison is not controlled.
    """
    from pathlib import Path

    from cli.explain import TASKS, _fresh_llm, _pick_task

    recorded = [
        name for name in TASKS if Path(f"agent/cassettes/{name}.json").exists()
    ]
    assert recorded, "no scenario has a recording yet"
    for name in recorded:
        # Runnable without --live, precisely because a recording exists.
        assert _pick_task(["--task", name], live=False)[0] == name
        task = (name, TASKS[name])
        first, second = _fresh_llm(False, task), _fresh_llm(False, task)
        assert first is not second, "each profile needs its own replay position"
        assert first.name == second.name == f"recorded — {name}.json"
        # Same transcript, so any difference in outcome has one cause.
        assert [first.next_step([]) for _ in range(3)] == [
            second.next_step([]) for _ in range(3)
        ]


def test_a_recording_is_accompanied_by_its_compliance_rate():
    """A cassette without one invites the reader to assume the model always
    complies. It did not: the rate is the honest headline."""
    import json
    from pathlib import Path

    for meta_path in Path("agent/cassettes").glob("*.meta.json"):
        meta = json.loads(meta_path.read_text())
        assert 0 < meta["complied"] <= meta["attempts"], meta_path
        assert meta["model"], meta_path
        if meta.get("criterion", "").startswith("caused"):
            # An injection recording exists to show the model complying, so a
            # run that did nothing would be recording the wrong thing.
            assert any(meta["damage_unguarded"].values()), (
                f"{meta_path} claims compliance but records no damage"
            )


def test_the_live_matrix_replays_one_sample_through_both_profiles():
    """A model cannot be sampled twice and asked to behave the same way.

    So the live matrix runs it once unguarded and replays that exact transcript
    through the broker. Sampling a second time would let the model take a
    different path, and the comparison would silently stop being about the
    broker — which is not hypothetical: inject-vendor once leaked 119 bytes
    unguarded and recorded zero refusals guarded, in one command.
    """
    from agent.llm import Cassette

    steps = [
        {"type": "tool_use", "tool": "read_document", "args": {"doc_id": "ticket-4711"}},
        {"type": "tool_use", "tool": "query_customers", "args": {"filter": "id=8812"}},
        {"type": "final", "text": "done"},
    ]
    replay = Cassette.from_steps(steps, "inject-vendor")
    assert replay.name == "replay of a live run — inject-vendor"
    assert [replay.next_step([]) for _ in range(3)] == steps
    # Independent replay position per profile, or the second run starts midway.
    a, b = Cassette.from_steps(steps), Cassette.from_steps(steps)
    assert a.next_step([]) == b.next_step([]) == steps[0]
    # The captured list is copied, not aliased: mutating the source afterwards
    # must not change what the guarded side replays.
    source = list(steps)
    held = Cassette.from_steps(source)
    source.clear()
    assert held.next_step([]) == steps[0]


def test_matrix_header_says_which_model_produced_it():
    """A live matrix and a recorded one look identical otherwise, and the
    difference decides what the table can be used to argue."""
    from cli.explain import render_matrix

    rows = [{"scenario": "export", "rule": "egress.allowlist",
             "harm": "155 bytes out", "guarded": "1 refused, 0 bytes out"}]
    assert "recorded model" in render_matrix(rows, live=False)
    assert "live model, replayed through the broker" in render_matrix(rows, live=True)
