# B3 — audit segment rotation, implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans`
> to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** `append()` closes the active segment when it crosses
`[audit].segment_bytes` and starts a new one whose first record anchors to the
one that closed, so a rotated log still verifies end to end and no writer can
put a record into a segment that is no longer active.

**Architecture:** The active segment keeps `[audit].path` forever; closed
segments are siblings named `<stem>-<last seq, 6 digits><suffix>`. Rotation
happens inside `append()`, under the existing `flock`, as staging file →
`os.link` → directory fsync → `os.replace` → directory fsync, so the active
name is never empty and never absent. Every append re-checks that the
descriptor it locked is still the file `[audit].path` names, and reopens if it
is not. Readers walk the anchors backward from the active segment.

**Tech stack:** Python 3.11, stdlib only (`fcntl`, `os`, `re`, `json`). pytest.

## Global constraints

- Designed in
  [`docs/superpowers/specs/2026-08-06-p2b3-audit-segment-rotation-design.md`](../specs/2026-08-06-p2b3-audit-segment-rotation-design.md).
  Every decision number below refers to that file.
- `ruff.toml`: `line-length = 100`, `target-version = "py311"`, isort with
  `known-first-party = ["warden", "demo", "tools", "tests"]` — **an import added
  to a sorted block must keep it sorted**; `ruff check . --fix` does it.
- The five gates, before every commit:
  `.venv/bin/pytest -q` · `.venv/bin/ruff check .` ·
  `.venv/bin/mypy warden --ignore-missing-imports` ·
  `opa test warden/policies/ demo/scenario/data.json` ·
  `.venv/bin/warden-demo explain --quiet-why`.
  Task 2 touches `demo/scenario/*.toml`, so it additionally needs
  `.venv/bin/warden-demo explain --matrix --quiet-why` to run to completion.
- Baseline at the start of this plan: **852 passed**, ruff clean, mypy clean on
  35 source files.
- `tests/golden/audit-4711.jsonl` is a frozen chain. Never regenerate it.
- `DEFAULT_SEGMENT_BYTES = 64 * 1024 * 1024`. `0` means never rotate.
- The anchor's thirteen body fields are exactly: `task_id="-"`,
  `agent_id="warden"`, `purpose="audit-segment-rotation"`,
  `action={"type": "anchor"}`,
  `target={"kind": "segment", "previous": "<closed file name>"}`,
  `args_digest="none"`, `decision="none"`, `rule="audit.rotation"`,
  `task_state=empty_task_state()`, `policy_bundle_digest="none"`, plus `seq`,
  `ts` and `prev_hash` from the chain.

---

## File structure

| file | responsibility after this plan |
|---|---|
| `warden/broker/audit.py` | one log, made of one or more segment files: appending, rotating, and assembling |
| `warden/broker/record_fields.py` | unchanged code; `empty_task_state`'s docstring gains its third caller |
| `warden/broker/config/loader.py` | `audit_segment_bytes` on `BrokerConfig` and `ControlConfig` |
| `warden/broker/__main__.py`, `warden/broker/control_main.py` | pass it to the `AuditLog` they build |
| `warden/cli/replay.py` | `_describe`'s fourth `action.type` branch |
| `demo/cli/explain.py` | `NarratedAudit` forwards `segments()` |
| `demo/scenario/warden.toml`, `demo/scenario/control.toml` | the new key, with its note |
| `docs/ROADMAP.md`, `docs/ARCHITECTURE.md` | B3 struck, § B's exit updated, the audit row says "segments" |

Three commits: the mechanism, then the config surface and the docs, then the
mutation pass. Same shape as B2, and for the same reason — the mechanism is
provable on its own, and a config key with nothing behind it is the one thing
this loader exists to prevent.

---

## Task 1 — the mechanism

**Files:**
- Modify: `warden/broker/audit.py`
- Modify: `warden/broker/record_fields.py` (docstring only)
- Test: `tests/warden/test_audit.py`

**Interfaces produced** (Task 2 and B4 depend on these exact names):
- `DEFAULT_SEGMENT_BYTES: int`
- `AuditLog(path, *, lock_timeout=..., durability=..., segment_bytes=DEFAULT_SEGMENT_BYTES)`
- `AuditLog.segment_bytes: int` — public, like `durability`
- `AuditLog.segments() -> list[Path]` — oldest first, active segment last
- `AuditLog.records()` and `AuditLog.verify_chain()` — unchanged signatures,
  now spanning every segment

- [ ] **Step 1: write the failing tests.** Append this whole block to
  `tests/warden/test_audit.py`. It is the spec's proof table, rows 1–19 and
  24–27.

```python
# --- B3: segment rotation ---------------------------------------------------
#
# Designed in docs/superpowers/specs/2026-08-06-p2b3-audit-segment-rotation-design.md.
# The invariant everything here defends: the name in [audit].path never refers
# to an empty file once the log has a history. Spiked before any of this was
# written -- rename the active file away and let the next append recreate it and
# the log restarts at seq 1 from genesis, with every record still verifying and
# verify_chain() over the active file returning (True, None).


def _fill_to_threshold(log, path, threshold):
    """Append until the active segment is at or over `threshold`.

    Returns the records written. A count would be a guess: a record's width is
    not fixed (see the tail-window test), so the loop watches the file.
    """
    written = [_append(log)]
    while path.stat().st_size < threshold:
        written.append(_append(log))
    return written


def test_crossing_the_threshold_closes_a_segment(tmp_path):
    """Row 1. The closed segment is named for the seq of its LAST record --
    which the tail read already has in hand, so naming costs no extra read."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    written = _fill_to_threshold(log, path, 4096)
    last_before = written[-1]["seq"]

    _append(log)

    closed = tmp_path / f"audit-{last_before:06d}.jsonl"
    assert closed.exists(), sorted(p.name for p in tmp_path.iterdir())
    assert [r["seq"] for r in json_lines(closed)] == list(range(1, last_before + 1))


def test_the_new_segment_holds_its_anchor_before_it_is_the_active_segment(tmp_path):
    """Row 2, and the whole of B3.

    The active name must go straight from the old inode to a new one that
    ALREADY contains the anchor. A rotation that renames the active file away
    and lets "a+b" recreate it leaves _head_from_tail reading an empty file,
    which answers (0, GENESIS_HASH) -- and the log restarts at seq 1 with every
    record still verifying.

    Asserted on the FIRST LINE of the active segment rather than by racing a
    reader against the swap: if the anchor is line 1 of the file that carries
    the active name, no reader can ever observe that name as empty.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    _fill_to_threshold(log, path, 4096)
    _append(log)

    first, second = json_lines(path)[:2]
    assert first["action"] == {"type": "anchor"}
    assert first["prev_hash"] != GENESIS_HASH
    assert second["prev_hash"] == first["hash"]


def test_a_rotated_log_verifies_end_to_end(tmp_path):
    """Row 3. Dense seqs across every segment, and a chain that verifies from
    genesis -- read by a SECOND AuditLog, so the assertion is about the files
    and not about one object agreeing with itself."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(60):
        _append(log)

    reader = AuditLog(path, segment_bytes=4096)
    assert len(reader.segments()) > 2, "the log never rotated"
    seqs = [r["seq"] for r in reader.records()]
    assert seqs == list(range(1, len(seqs) + 1))
    assert reader.verify_chain() == (True, None)


def test_the_anchor_names_the_previous_segment(tmp_path):
    """Row 4. The name is what the anchor adds: prev_hash already carries the
    previous segment's head hash. Without the name, an operator who archives
    the oldest segment leaves a log whose first record links to a hash nobody
    can produce -- indistinguishable from tampering."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    written = _fill_to_threshold(log, path, 4096)
    _append(log)

    anchor = json_lines(path)[0]
    assert anchor["target"] == {
        "kind": "segment",
        "previous": f"audit-{written[-1]['seq']:06d}.jsonl",
    }
    assert anchor["prev_hash"] == written[-1]["hash"]


def test_an_anchor_has_exactly_a_decision_records_fields(tmp_path):
    """Row 5. One record shape, on B7's decision 9: the mint reused the
    thirteen body fields so AuditLog needed no new field, and so does this.

    Compared against a real decision record rather than a hardcoded list, so
    a field added to the record shape without being added to the anchor fails
    here -- and a field added to both still has to face
    test_a_written_record_has_exactly_these_fields, which IS hardcoded.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    _fill_to_threshold(log, path, 4096)
    decision = _append(log)

    anchor = json_lines(path)[0]
    assert sorted(anchor) == sorted(decision)
    assert anchor["task_id"] == "-"
    assert anchor["agent_id"] == "warden"
    assert anchor["decision"] == "none"
    assert anchor["rule"] == "audit.rotation"
    assert anchor["args_digest"] == "none"
    assert anchor["policy_bundle_digest"] == "none"
    # Forced, not chosen: warden/cli/replay.py subscripts
    # task_state["data_classes_held"] for every record before printing
    # anything, so {} tracebacks the one tool that renders the log.
    assert anchor["task_state"] == {"data_classes_held": [], "rows_charged_so_far": 0}


_ROTATING_APPEND_SCRIPT = """
import sys
from warden.broker.audit import AuditLog

log = AuditLog(sys.argv[1], durability="flush", segment_bytes=int(sys.argv[3]))
for _ in range(int(sys.argv[2])):
    log.append(
        task_id="4711",
        agent_id="triage-bot",
        purpose="support-triage",
        action={"type": "tool_call", "tool": "read_document"},
        target={"kind": "doc"},
        args_digest="sha256:aaa",
        decision="allow",
        rule="tools.allowed",
        task_state={"data_classes_held": [], "rows_charged_so_far": 0},
        policy_bundle_digest="sha256:bbb",
    )
"""


def test_four_processes_rotating_produce_one_intact_chain(tmp_path):
    """Row 6, the load-bearing one, and B6's test with rotation switched on.

    Measured against a build with the staleness check removed -- four
    processes, 40 appends each, a 4KiB segment, three runs: 3 of 4 writers dead
    every run, 35 to 75 of 160 appends returning at all, and what survived was
    either a chain BROKEN at seq 33 or a log that refuses to be read. The
    mechanism is not the obvious one: a writer holding a rotated-away
    descriptor does not merely append into the closed segment, it finds that
    segment still over the threshold and tries to ROTATE it, forking the
    segment tree.

    A 4KiB segment holds ~8 records, so rotation happens roughly every other
    append across four processes -- violently more often than any real
    deployment, which is the point.

    Fresh interpreters, never multiprocessing: tests/ has no __init__.py and
    pytest.ini sets --import-mode=importlib, so a spawn child cannot re-import
    the test module, and forking a multi-threaded pytest process is a
    documented deadlock hazard.
    """
    path = tmp_path / "audit.jsonl"
    procs, per_proc = 4, 40
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", _ROTATING_APPEND_SCRIPT, str(path), str(per_proc), "4096"],
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(procs)
    ]
    for worker in workers:
        _, stderr = worker.communicate(timeout=300)
        assert worker.returncode == 0, stderr

    log = AuditLog(path, segment_bytes=4096)
    records = log.records()
    decisions = [r for r in records if r["action"]["type"] != "anchor"]
    assert len(decisions) == procs * per_proc
    assert len(log.segments()) > 5, "the log never rotated"
    # Dense over EVERY record, anchors included: an anchor occupies a seq, so a
    # chain with a gap is a chain with a record nobody has.
    assert [r["seq"] for r in records] == list(range(1, len(records) + 1))
    assert log.verify_chain() == (True, None)


def test_a_writer_whose_segment_was_rotated_away_reopens(tmp_path):
    """Row 7, deterministically -- the process test above is a race by nature.

    Rotates the log from INSIDE _acquire, so the descriptor append() locked is
    guaranteed stale by the time it is inspected. Without the staleness check
    the record lands in the closed segment, with a prev_hash the new segment's
    anchor also claims: two records with one predecessor, which is the fork.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    _fill_to_threshold(log, path, 4096)
    rotator = AuditLog(path, segment_bytes=4096)

    real_acquire = audit_module._acquire
    rotations = []

    def acquire_then_rotate(handle, timeout):
        real_acquire(handle, timeout)
        if not rotations:
            rotations.append(_append(rotator))  # rotates, once

    with patch.object(audit_module, "_acquire", acquire_then_rotate):
        record = _append(log)

    closed = tmp_path / f"audit-{rotations[0]['seq'] - 1:06d}.jsonl"
    assert record["seq"] == rotations[0]["seq"] + 1
    assert json_lines(closed)[-1]["seq"] == rotations[0]["seq"] - 1, (
        "a record was appended into the closed segment"
    )
    assert AuditLog(path, segment_bytes=4096).verify_chain() == (True, None)


def test_endless_rotation_gives_up_within_one_lock_timeout(tmp_path):
    """Rows 8 and 27. Bounded, and bounded by ONE lock_timeout for the whole
    call rather than one per attempt: giving each attempt a fresh five seconds
    would let a retrying append hold a threadpool thread for a multiple of the
    constant whose own comment says one wedged writer must not wedge every
    worker.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096, lock_timeout=0.3)
    _fill_to_threshold(log, path, 4096)
    rotator = AuditLog(path, segment_bytes=1)

    real_acquire = audit_module._acquire

    def acquire_then_rotate(handle, timeout):
        real_acquire(handle, timeout)
        _append(rotator)  # rotates on EVERY attempt

    started = time.monotonic()
    with patch.object(audit_module, "_acquire", acquire_then_rotate):
        with pytest.raises(OSError, match="rotated out from under this writer"):
            _append(log)
    assert time.monotonic() - started < 3.0


def test_a_threshold_below_one_record_still_makes_progress(tmp_path):
    """Row 9. At most one rotation per append() call, so any threshold
    terminates. Without the flag, a threshold below one record makes every
    append rotate, reopen, find the new segment also over the threshold, and
    rotate again until the deadline -- so appends FAIL rather than merely
    producing tiny segments."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=1)
    for _ in range(5):
        _append(log)

    reader = AuditLog(path, segment_bytes=1)
    records = reader.records()
    assert [r["seq"] for r in records] == list(range(1, len(records) + 1))
    assert sum(1 for r in records if r["action"]["type"] != "anchor") == 5
    assert reader.verify_chain() == (True, None)


def test_rotation_fsyncs_the_directory_before_and_after_the_replace(tmp_path):
    """Rows 10 and 26.

    The SECOND directory fsync is durability -- the record is written into the
    new segment after the replace, so a replace that is not durable leaves it
    in a nameless inode, which is B2's failure one level up.

    The FIRST one is ordering, and it is the one that is easy to leave out.
    The link and the replace are both unfsynced directory metadata and POSIX
    orders neither; a filesystem free to make the replace durable while the
    link is not would leave the closing segment with NO NAME and its records
    unrecoverable. Journalling filesystems happen not to do that. This does not
    depend on it.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    _fill_to_threshold(log, path, 4096)

    seen: list[str] = []
    real = os.fsync

    def spy(fd: int) -> None:
        seen.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real(fd)

    with patch.object(os, "fsync", spy):
        _append(log)

    # staging file, directory (before the replace), directory (after it), then
    # the record's own file.
    assert seen == ["file", "dir", "dir", "file"]


def test_flush_durability_does_not_fsync_a_rotation(tmp_path):
    """Row 10's other half. "flush" promises the page cache, not the device;
    spending 3.1ms per rotation to half-honour a promise the operator declined
    is how a config key comes to mean two things."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, durability="flush", segment_bytes=4096)
    _fill_to_threshold(log, path, 4096)

    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        _append(log)
    assert seen == []
    assert AuditLog(path, segment_bytes=4096).verify_chain() == (True, None)


def test_a_crash_between_link_and_replace_is_readable_and_completes(tmp_path):
    """Row 11. The rotation is not atomic as a whole, and the window between
    the link and the replace leaves the closing segment with TWO names, one of
    which is still the active one.

    Identity is (st_dev, st_ino), not the name: a draft that compared resolved
    paths reported `segment files nothing in the chain names` for a log that
    was completely fine, and left it unreadable until the next rotation --
    64MiB of writes later.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    written = _fill_to_threshold(log, path, 4096)
    closed = tmp_path / f"audit-{written[-1]['seq']:06d}.jsonl"
    os.link(path, closed)  # the crash: linked, not yet replaced

    during = AuditLog(path, segment_bytes=4096)
    assert [r["seq"] for r in during.records()] == [r["seq"] for r in written]
    assert during.verify_chain() == (True, None)

    _append(log)
    after = AuditLog(path, segment_bytes=4096)
    assert [r["seq"] for r in after.records()] == list(range(1, len(written) + 2))
    assert after.verify_chain() == (True, None)


def test_a_foreign_file_at_the_closed_name_refuses_the_rotation(tmp_path):
    """Row 12. The same-inode branch above must not become a blanket
    "FileExistsError means carry on", or a file that is not this log gets
    absorbed into the chain as a segment."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    written = _fill_to_threshold(log, path, 4096)
    stranger = tmp_path / f"audit-{written[-1]['seq']:06d}.jsonl"
    stranger.write_text("someone else's file\n")

    with pytest.raises(
        OSError,
        match=f"audit segment {stranger.name} already exists and is not this log",
    ):
        _append(log)


def test_an_emptied_active_segment_beside_segments_refuses_the_append(tmp_path):
    """Row 13. An operator deleting the active file while segments exist is
    the spiked fork arriving by another route: "a+b" recreates it, the tail
    read answers genesis, and the log acquires a second chain that verifies."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    assert len(AuditLog(path, segment_bytes=4096).segments()) > 1
    path.unlink()

    with pytest.raises(
        OSError, match="refusing to start a second chain at genesis"
    ):
        _append(log)


def test_a_newline_only_active_segment_refuses_the_append(tmp_path):
    """Row 24. Gated on the HEAD reading as genesis, not on st_size == 0:
    _head_from_tail documents a second way to read as genesis -- a file of
    nothing but newlines -- so a size test leaves a hole in exactly the place
    the code it guards already has a special case."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    path.write_bytes(b"\n\n")

    with pytest.raises(
        OSError, match="refusing to start a second chain at genesis"
    ):
        _append(log)


def test_an_absent_predecessor_refuses_the_read(tmp_path):
    """Row 14. Pruning an audit log is a real operator need and B3 does not
    serve it. Refusing names both files; verifying the available suffix instead
    would report `chain BROKEN at seq N` -- calling a deliberate operator
    action tampering."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    oldest = AuditLog(path, segment_bytes=4096).segments()[0]
    namer = AuditLog(path, segment_bytes=4096).segments()[1]
    oldest.unlink()

    with pytest.raises(
        OSError,
        match=f"audit segment {oldest.name} is missing, named by {namer.name}",
    ):
        AuditLog(path, segment_bytes=4096).records()


def test_an_anchor_naming_a_path_refuses_the_read(tmp_path):
    """Row 15. A log is precisely the artifact that may have been hand-edited,
    so a crafted anchor must not become a file this code opens."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)

    lines = path.read_text().splitlines()
    doctored = json.loads(lines[0])
    doctored["target"]["previous"] = "../../etc/passwd"
    lines[0] = json.dumps(doctored, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(
        OSError, match=r"anchors to an illegal name: '\.\./\.\./etc/passwd'"
    ):
        AuditLog(path, segment_bytes=4096).records()


def test_orphaned_segments_refuse_the_read(tmp_path):
    """Row 16. Every closed-segment-shaped file in the directory must be
    reachable from the active segment's anchors. This is what catches a log
    that forked: the fork's segments are on disk, and nothing names them."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    (tmp_path / "audit-999999.jsonl").write_text("{}\n")

    with pytest.raises(
        OSError, match=r"segment files nothing in the chain names: \['audit-999999.jsonl'\]"
    ):
        AuditLog(path, segment_bytes=4096).records()


def test_an_anchor_cycle_refuses_the_read(tmp_path):
    """Row 17. A hand-edited pair of anchors naming each other is an infinite
    walk, and an audit tool that hangs is an audit tool that gets skipped."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)

    segments = AuditLog(path, segment_bytes=4096).segments()
    oldest, second = segments[0], segments[1]
    # Give the oldest segment an anchor pointing forward at its own successor.
    anchor = json_lines(second)[0]
    anchor["target"]["previous"] = second.name
    oldest.write_text(json.dumps(anchor, sort_keys=True) + "\n" + oldest.read_text())

    with pytest.raises(OSError, match="anchors form a cycle"):
        AuditLog(path, segment_bytes=4096).records()


def test_a_log_written_before_segments_still_reads_and_rotates(tmp_path):
    """Row 18. Zero migration: an unrotated single-file log IS segment 0, whose
    first record links to genesis and which carries no anchor."""
    path = tmp_path / "audit.jsonl"
    old = AuditLog(path, segment_bytes=0)  # what shipped before B3
    for _ in range(5):
        _append(old)

    log = AuditLog(path, segment_bytes=4096)
    assert log.segments() == [path]
    assert len(log.records()) == 5
    assert log.verify_chain() == (True, None)

    for _ in range(40):
        _append(log)
    assert len(log.segments()) > 1
    assert log.verify_chain() == (True, None)


def test_a_path_with_no_suffix_rotates(tmp_path):
    """Row 19. [audit].path is a string an operator writes; nothing makes it
    end in .jsonl."""
    path = tmp_path / "auditlog"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)

    reader = AuditLog(path, segment_bytes=4096)
    assert len(reader.segments()) > 1
    assert reader.segments()[0].name.startswith("auditlog-0")
    assert reader.verify_chain() == (True, None)


def test_a_path_with_glob_metacharacters_still_finds_its_segments(tmp_path):
    """Row 25. Path.glob interprets its argument as a PATTERN, so a stem
    containing [ ] * or ? would make the orphan scan search a different set of
    names than the segment pattern accepts -- and the mismatch empties the
    guard rather than tripping it."""
    path = tmp_path / "audit[1].jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    assert len(AuditLog(path, segment_bytes=4096).segments()) > 1
    path.unlink()

    with pytest.raises(
        OSError, match="refusing to start a second chain at genesis"
    ):
        _append(log)


def test_segment_bytes_zero_never_rotates(tmp_path):
    """The escape hatch, and what shipped before B3."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=0)
    for _ in range(60):
        _append(log)
    assert AuditLog(path, segment_bytes=0).segments() == [path]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit.jsonl"]


def test_the_default_segment_size_is_64_mib(tmp_path):
    """Row 21's constructor half. On by default: a deployment that reaches
    64MiB has ~123,000 records and a real operational problem, and one that
    never reaches it is unaffected."""
    assert DEFAULT_SEGMENT_BYTES == 64 * 1024 * 1024
    assert AuditLog(tmp_path / "audit.jsonl").segment_bytes == DEFAULT_SEGMENT_BYTES


def test_a_negative_segment_bytes_is_refused_by_the_constructor(tmp_path):
    """Row 22. Same discipline as `durability`: never a silent fallback."""
    with pytest.raises(
        ValueError, match=r"audit segment_bytes must be a non-negative integer, got -1"
    ):
        AuditLog(tmp_path / "audit.jsonl", segment_bytes=-1)
```

  The block above needs four things at the top of the file. Add `stat` to the
  imports, keeping them sorted; import the module itself so `_acquire` has a
  patch point; and add the `json_lines` helper beside `_append`:

```python
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from warden.broker import audit as audit_module
from warden.broker.audit import (
    DEFAULT_SEGMENT_BYTES,
    GENESIS_HASH,
    AuditLog,
    canonical_json,
)


def json_lines(path) -> list[dict]:
    """Every record in ONE file, read directly.

    Deliberately not AuditLog.records(), which spans segments: several tests
    below are about which file a record landed in, and a helper that hides
    that would make them pass against the bug they name.
    """
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
```

- [ ] **Step 2: run them and watch them fail.**

Run: `.venv/bin/pytest tests/warden/test_audit.py -q 2>&1 | tail -20`
Expected: collection succeeds, and every new test fails — `ImportError` on
`DEFAULT_SEGMENT_BYTES` would mean the whole *file* errors, so fix the import
first if that happens and confirm the failures are `TypeError: __init__() got an
unexpected keyword argument 'segment_bytes'` rather than a collection error.
**A collection error is not a red test.** A mutation or a first draft that does
not compile reddens nothing and looks exactly like a gap.

- [ ] **Step 3: the module-level additions to `warden/broker/audit.py`.**

Add `re` to the imports (sorted: `fcntl, hashlib, json, os, re, threading,
time`). Add the import of the shared vocabulary below them:

```python
from warden.broker.record_fields import empty_task_state
```

This is the first thing `audit.py` has ever imported from inside `warden`. It
costs nothing measurable and it is the right direction: `record_fields` exists
because "two processes must agree on what a field means or the chain is one file
containing two vocabularies", and `_rotate` below makes `audit.py` a **third**
writer. `record_fields` imports nothing but the standard library, and the two
processes that hold an `AuditLog` already import it.

Then, after `_TAIL_WINDOW_BYTES`:

```python
# Where a segment closes, in bytes of the active segment, checked before the
# record that would cross it. A closed segment is therefore at least this and
# at most this plus one record.
#
# ON by default, unlike `flush` -> `fsync` which was a default CHANGE: a
# deployment that reaches 64MiB has ~123,000 records at the 547 bytes one
# measures here and a real operational problem -- one file no editor opens,
# that records() loads whole into memory, and that cannot be archived in parts.
# A deployment that never reaches it is untouched, which is every test in this
# suite and the demo's eight records.
#
# 64MiB and not 16 (33 segments per million records) or 256 (2): ROADMAP § B's
# exit is a million-record log that VERIFIES ACROSS ROTATION, and ~8 segments
# is the granularity that actually exercises that.
#
# 0 disables rotation entirely, which is what shipped before B3. Not a separate
# flag, because the loader's _positive(..., allow_zero=True) already means
# exactly this and one key cannot then disagree with another.
DEFAULT_SEGMENT_BYTES = 64 * 1024 * 1024

# The `action.type` of the record that opens every segment after the first.
# Named once: audit.py writes it, warden/cli/replay.py renders it, and a
# fourth writer of this string would be a third vocabulary.
ANCHOR_ACTION_TYPE = "anchor"
```

- [ ] **Step 4: the two module-level helpers**, after `_head_from_tail`:

```python
def _identity(path: Path) -> tuple[int, int]:
    """WHICH FILE a name refers to, rather than which name.

    Rotation deliberately gives the closing segment two names for a moment
    (see AuditLog._rotate), and a crash in that window leaves them both. Every
    "is this the same file" question in this module therefore has to be asked
    about the inode: comparing resolved paths reports a log that is entirely
    fine as having `segment files nothing in the chain names`, and leaves it
    unreadable until the next rotation.
    """
    info = os.stat(path)
    return info.st_dev, info.st_ino


def _still_the_active_segment(handle: BinaryIO, path: Path) -> bool:
    """Whether the locked descriptor is the file `path` names RIGHT NOW.

    This is B6 for a log that rotates. A writer opens `path`, then spins for
    the flock; another writer holding that lock rotates; and the first writer
    now holds a descriptor on a segment that has been closed. Its size is still
    over the threshold, so it does not merely append into a closed file -- it
    tries to ROTATE it, and produces a second, divergent lineage of segments.

    Measured with this check removed: four processes, 40 appends each, a 4KiB
    segment, three runs -- 3 of 4 writers dead every run, 35 to 75 of 160
    appends returning at all, and what survived was either a chain BROKEN at
    seq 33 or a log that refuses to be read at all.

    A missing name counts as rotated away: reopening recreates it, and the
    genesis guard in append() is what then refuses to start a second chain.
    """
    held = os.fstat(handle.fileno())
    try:
        named = os.stat(path)
    except FileNotFoundError:
        return False
    return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)


def _anchor_of(path: Path) -> dict | None:
    """A segment's anchor record, or None if it does not begin with one.

    readline() rather than the tail read's doubling window: reading FORWARD to
    the first newline needs no window at all, whatever the record's width.

    Every "not an anchor" answer here is deliberately quiet, including a first
    line that is not JSON. This function answers one question -- what does this
    segment follow -- and `verify_chain` is what reports a corrupt record.
    """
    with path.open("rb") as handle:
        first = handle.readline()
    if not first.strip():
        return None
    try:
        record = json.loads(first)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None
    action = record.get("action")
    if not isinstance(action, dict) or action.get("type") != ANCHOR_ACTION_TYPE:
        return None
    return record
```

- [ ] **Step 5: the constructor.** Add the parameter, the validation and the
  public attribute:

```python
        segment_bytes: int = DEFAULT_SEGMENT_BYTES,
    ) -> None:
```

```python
        if not isinstance(segment_bytes, int) or segment_bytes < 0:
            # Never a silent fallback, exactly as `durability` above: a
            # threshold this object quietly ignored would be a deployment
            # whose log grows without bound while its config says otherwise.
            raise ValueError(
                f"audit segment_bytes must be a non-negative integer, got {segment_bytes!r}"
            )
```

```python
        # PUBLIC, alongside `path` and `durability`, and for the same reason:
        # broker/__main__.py's build() returns its BrokerComponents, so a test
        # can assert the configured value reached the log rather than mocking
        # the constructor call.
        self.segment_bytes = segment_bytes
```

- [ ] **Step 6: the reading side.** Replace `records()` with:

```python
    def segments(self) -> list[Path]:
        """Every file this log is made of, OLDEST FIRST, active segment last.

        Walked BACKWARD from the active segment through the anchors, not
        globbed and sorted. The walk is content, so no filename can lie about
        where a segment belongs, no naming pattern has to be authoritative, and
        a missing segment is diagnosable AS a missing segment rather than as a
        hash mismatch at an arbitrary seq. Measured: 27us per segment, which is
        3% on a 26-segment log, so there is nothing here worth caching.

        PUBLIC, like `durability`: B4 is about teaching the CLI what a
        segmented log is, and a test that asserts which files a log is made of
        should read the answer rather than mock its way to one.
        """
        if not self.path.exists():
            # records() answers "zero records" for a log that is not there and
            # warden/cli/replay.py depends on that (it checks for the missing
            # file itself, first, and exits 2). This answers the matching
            # question the same way rather than raising where its caller does
            # not.
            return []
        chain = [self.path]
        seen = {_identity(self.path)}
        cursor = self.path
        while (anchor := _anchor_of(cursor)) is not None:
            target = anchor.get("target")
            previous = target.get("previous") if isinstance(target, dict) else None
            if not isinstance(previous, str) or not previous or previous != Path(previous).name:
                # A log is precisely the artifact that may have been
                # hand-edited, so a crafted anchor must not become a file this
                # code opens. `previous != Path(previous).name` rejects every
                # separator, "..", "." and the empty string in one comparison.
                raise OSError(
                    f"audit segment {cursor.name} anchors to an illegal name: {previous!r}"
                )
            older = self.path.parent / previous
            if not older.exists():
                # Refused, not skipped. Verifying whatever suffix is present
                # reports `chain BROKEN at seq N`, which calls a deliberate
                # operator action tampering; returning the partial log silently
                # is worse, because `warden replay` would then print `chain
                # intact` over a log missing its beginning. Pruning an audit
                # log is a real need and B3 does not serve it.
                raise OSError(
                    f"audit segment {previous} is missing, named by {cursor.name}"
                )
            if _identity(older) in seen:
                # A hand-edited pair of anchors naming each other is an
                # infinite walk, and an audit tool that hangs is one that gets
                # skipped.
                raise OSError(f"audit segment anchors form a cycle at {previous}")
            seen.add(_identity(older))
            chain.append(older)
            cursor = older
        strangers = [
            entry.name for entry in self._closed_segment_files()
            if _identity(entry) not in seen
        ]
        if strangers:
            # Every closed-segment-shaped file here must be reachable from the
            # active segment. This is what catches a log that FORKED: the
            # fork's segments are on disk and nothing names them, and without
            # this the log reads as a short, perfectly intact chain.
            raise OSError(
                f"audit log has segment files nothing in the chain names: {strangers}"
            )
        return list(reversed(chain))

    def _closed_segment_name(self, last_seq: int) -> str:
        """`audit.jsonl` closing at seq 8 becomes `audit-000008.jsonl`.

        Named for the seq of its LAST record, which the tail read already has
        in hand at rotation time, so naming costs no extra read. Unique by
        construction, because seqs are. Past 999,999 it grows a seventh digit
        and stops sorting lexically, which costs nothing: order comes from the
        anchors, not from the names.
        """
        return f"{self.path.stem}-{last_seq:06d}{self.path.suffix}"

    def _closed_segment_files(self) -> list[Path]:
        """Every sibling shaped like a closed segment of THIS log.

        iterdir() and a compiled pattern, never Path.glob: glob interprets its
        argument as a pattern, so a `[audit].path` containing [ ] * or ? would
        search a different set of names than the pattern accepts -- and that
        mismatch EMPTIES the orphan guard rather than tripping it. iterdir()
        lists the directory once, which glob does anyway.
        """
        pattern = re.compile(
            re.escape(self.path.stem) + r"-\d{6,}" + re.escape(self.path.suffix)
        )
        return sorted(
            entry for entry in self.path.parent.iterdir() if pattern.fullmatch(entry.name)
        )

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for segment in self.segments()
            for line in segment.read_text().splitlines()
            if line.strip()
        ]
```

- [ ] **Step 7: `_rotate` and `_fsync_directory`**, before `append`:

```python
    def _fsync_directory(self) -> None:
        """fsync on a FILE makes its contents durable and says nothing about
        the directory entry that makes it findable. B2 established this for
        the log's first record; rotation needs it twice per rotation."""
        if self.durability != "fsync":
            return
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _rotate(self, handle: BinaryIO) -> None:
        """Close the segment `handle` holds and make a new one the active one.

        Called under the flock on `handle`, which is what makes the head read
        below still the head when the anchor is built from it.

        The order is the whole design. `[audit].path` must never, at any
        instant, refer to an empty file once the log has a history: the naive
        rotation -- rename the active file away and let the next append's "a+b"
        recreate it -- leaves _head_from_tail reading an empty file, which
        answers (0, GENESIS_HASH), and the log restarts at seq 1 with every
        record still verifying and verify_chain() returning (True, None). Two
        chains in one log, both internally perfect, nothing saying so.

        So: the anchor is written to a staging file FIRST, and `[audit].path`
        goes straight from the old inode to a new one that already contains
        it. The link before the replace is what keeps the closing segment
        reachable, since the replace takes its name away.
        """
        seq, prev_hash = _head_from_tail(handle)
        closed = self.path.parent / self._closed_segment_name(seq)
        body = {
            "seq": seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            # Thirteen fields, the same thirteen every decision carries, on
            # B7's decision 9: a mint reused them precisely so the record shape
            # stays ONE shape and AuditLog needs no new field.
            #
            # The previous segment's head hash is `prev_hash` -- the field
            # every record already uses for exactly that. ROADMAP B3 called for
            # "an anchor record carrying the previous segment's head hash" and
            # anticipated a fourteenth field; the anchor is simply the chain's
            # next record, so none is needed. What it adds is the previous
            # segment's NAME, and that is what lets an operator archive the
            # oldest segment and leave something verifiable behind.
            "task_id": "-",
            "agent_id": "warden",
            "purpose": "audit-segment-rotation",
            "action": {"type": ANCHOR_ACTION_TYPE},
            "target": {"kind": "segment", "previous": closed.name},
            # Bare "none", no `sha256:` prefix, on B7's reasoning about that
            # exact choice: args_digest wears its prefix when arguments
            # conceptually existed and were deliberately not read. Here there
            # are no arguments at all.
            "args_digest": "none",
            # Not "allow": nothing was authorised. Not a new word either --
            # "none" is what this chain already says for a thing that did not
            # exist (policy_bundle_digest on a mint).
            "decision": "none",
            "rule": "audit.rotation",
            # The shape is forced, not chosen: warden/cli/replay.py subscripts
            # task_state["data_classes_held"] for every record before printing
            # anything, so {} tracebacks the one tool that renders the log --
            # and does so AFTER verify-chain reported it intact.
            "task_state": empty_task_state(),
            "policy_bundle_digest": "none",
            "prev_hash": prev_hash,
        }
        anchor = dict(body)
        anchor["hash"] = record_hash(body)
        staging = self.path.with_name(self.path.name + ".rotating")
        with staging.open("wb") as fresh:
            fresh.write((json.dumps(anchor, sort_keys=True) + "\n").encode("utf-8"))
            fresh.flush()
            if self.durability == "fsync":
                os.fsync(fresh.fileno())
        held = os.fstat(handle.fileno())
        try:
            os.link(self.path, closed)
        except FileExistsError:
            if _identity(closed) != (held.st_dev, held.st_ino):
                raise OSError(
                    f"audit segment {closed.name} already exists and is not this log"
                ) from None
            # Same inode: a previous rotation was interrupted between the link
            # and the replace below, and this completes it rather than
            # refusing. Reads during that window are already correct -- the
            # duplicate name is skipped by inode identity.
        # ORDERING, not durability. The replace below depends on both names
        # created above, and both are unfsynced directory metadata that POSIX
        # orders in no way at all: a filesystem free to make the replace
        # durable while the link is not would leave the closing segment with NO
        # NAME and its records unrecoverable. Journalling filesystems happen
        # not to do that; 1.4ms once per ~123,000 records buys not depending on
        # it.
        self._fsync_directory()
        os.replace(staging, self.path)
        # Durability, and B2's property one level up. The record this append is
        # about goes into the new segment AFTER this returns, and its bytes get
        # the existing per-append fsync -- but its NAME is this replace, so a
        # replace that is not durable leaves the record whose append() already
        # returned in a nameless inode.
        self._fsync_directory()
```

- [ ] **Step 8: `append`'s loop.** Replace the two lines

```python
            with self.path.open("a+b") as handle:
                _acquire(handle, self._lock_timeout)
```

  with the block below, indent the existing body from `seq, prev_hash =
  _head_from_tail(handle)` to `return record` by four spaces to sit under the
  new `else:`, and insert the genesis guard directly after the tail read:

```python
        # At most ONE rotation per call, tracked here rather than re-derived
        # from the file. Without it a segment_bytes below one record makes
        # every append rotate, reopen, find the new segment also over the
        # threshold and rotate again until the deadline -- so appends FAIL
        # rather than merely producing tiny segments.
        rotated = False
        with self._lock:
            # ONE deadline for the whole call, not one per attempt. Giving each
            # attempt a fresh lock_timeout would let a retrying append hold a
            # pool thread for a multiple of the constant whose own comment is
            # about one wedged writer not wedging every worker.
            deadline = time.monotonic() + self._lock_timeout
            while True:
                # "a+b": append-only writes, but READABLE, which is what lets
                # the head be taken from the tail of the same descriptor the
                # lock is held on. Path.open rather than the builtin so the
                # disk-full test keeps its patch point.
                with self.path.open("a+b") as handle:
                    _acquire(handle, max(0.0, deadline - time.monotonic()))
                    if not _still_the_active_segment(handle, self.path):
                        reason = "was rotated out from under this writer"
                    elif not rotated and self.segment_bytes and (
                        os.fstat(handle.fileno()).st_size >= self.segment_bytes
                    ):
                        self._rotate(handle)
                        rotated = True
                        reason = "was rotated by this writer"
                    else:
                        <the existing body, indented four spaces, ending in
                         `return record`>
                # Reopen: the file this writer holds is not the active segment
                # any more, either because someone else rotated it or because
                # this call just did. Outside the `with`, so the flock on the
                # segment that is no longer active is released before the
                # retry -- and before the OSError, which is the same type and
                # the same handlers as the flock timeout above.
                if time.monotonic() >= deadline:
                    raise OSError(f"audit log {self.path} {reason}: gave up")
```

  and the guard, immediately after `seq, prev_hash = _head_from_tail(handle)`:

```python
                        if (seq, prev_hash) == (0, GENESIS_HASH):
                            # This log has no records -- and if closed segments
                            # sit beside it, appending here would start a
                            # SECOND chain at genesis: the exact fork the
                            # rotation order above exists to prevent, arriving
                            # by another route (an operator deleting the active
                            # file). Gated on the HEAD rather than on
                            # st_size == 0, because _head_from_tail answers
                            # genesis for a file of nothing but newlines too.
                            #
                            # Runs once in a log's life, so the directory scan
                            # costs nothing in steady state.
                            strangers = [
                                entry.name
                                for entry in self._closed_segment_files()
                                if _identity(entry) != _identity(self.path)
                            ]
                            if strangers:
                                raise OSError(
                                    "audit log holds no records but segment files "
                                    "exist: refusing to start a second chain at "
                                    f"genesis ({strangers})"
                                )
```

  Also replace B2's inline directory-fsync block inside `append` with
  `self._fsync_directory()`, keeping its comment — one implementation of that
  syscall pair, not two.

- [ ] **Step 9: `record_fields.py`'s docstring** — `empty_task_state` enumerates
  its callers and what each means by the value. Add the third:

```python
      * audit.py writes it for a segment anchor, where there is no task at
        all. The shape is forced rather than meaningful: replay.py subscripts
        task_state["data_classes_held"] for every record it renders.
```

- [ ] **Step 10: run the new tests.**

Run: `.venv/bin/pytest tests/warden/test_audit.py -q 2>&1 | tail -20`
Expected: all pass. If `test_rotation_fsyncs_the_directory_before_and_after_the_replace`
reports `["file", "dir", "dir", "file"]` in a different order, the order in
`_rotate` is wrong, not the test.

- [ ] **Step 11: the full gates.**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy warden --ignore-missing-imports
opa test warden/policies/ demo/scenario/data.json
.venv/bin/warden-demo explain --quiet-why
```
Expected: 852 + the new tests, ruff and mypy clean, `explain` still showing
**8 records, 3 refusals, 1 record read**.

- [ ] **Step 12: measure what shipped**, so the numbers in the commit message
  are this code's and not the prototype's. Write to the scratchpad, not the
  repo:

```python
# per-append overhead against segment_bytes=0, interleaved; and the cost of a
# rotating append at both durability levels, now that there are two directory
# fsyncs.
```
Record: median plain append at both levels, median rotating append at both
levels, and records-per-64MiB-segment.

- [ ] **Step 13: commit.**

```bash
git add warden/broker/audit.py warden/broker/record_fields.py tests/warden/test_audit.py
git commit   # message: what was measured, and which mutation reddened which test
```

---

## Task 2 — the config surface, the wiring, and the docs

**Files:**
- Modify: `warden/broker/config/loader.py`, `warden/broker/__main__.py`,
  `warden/broker/control_main.py`, `warden/cli/replay.py`,
  `demo/cli/explain.py`, `demo/scenario/warden.toml`,
  `demo/scenario/control.toml`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`
- Test: `tests/warden/test_config_loader.py`, `tests/warden/test_key_split.py`,
  `tests/demo/test_cli.py`

**Interfaces consumed:** `DEFAULT_SEGMENT_BYTES`, `AuditLog(...,
segment_bytes=...)`, `AuditLog.segment_bytes`, `ANCHOR_ACTION_TYPE`.
**Produced:** `BrokerConfig.audit_segment_bytes`,
`ControlConfig.audit_segment_bytes`.

- [ ] **Step 1: the failing loader tests.** Append to
  `tests/warden/test_config_loader.py`, in the style of its B2 section:

```python
# --- B3: [audit].segment_bytes, in BOTH loaders -----------------------------
#
# Designed in docs/superpowers/specs/2026-08-06-p2b3-audit-segment-rotation-design.md.


def test_audit_segment_bytes_defaults_to_64_mib(tmp_path):
    """Every config written before this key existed must keep loading, and get
    the behaviour the product ships rather than the one it replaced."""
    config = load_broker_config(write(tmp_path, COMPLETE), env={})
    assert config.audit_segment_bytes == 64 * 1024 * 1024


def test_audit_segment_bytes_is_read_from_both_tomls(tmp_path):
    broker = load_broker_config(
        write(tmp_path, COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = 4096")),
        env={},
    )
    control = load_control_config(
        write(
            tmp_path / "c",
            CONTROL_COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = 8192"),
        ),
        env={},
    )
    assert (broker.audit_segment_bytes, control.audit_segment_bytes) == (4096, 8192)


def test_the_two_writers_may_choose_different_segment_bytes(tmp_path):
    """Like `durability` and unlike `path` and `issuer`: nothing compares
    these, and nothing should. A disagreement makes segment sizes irregular --
    whichever writer crosses its own threshold rotates -- which is untidy and
    not a misconfiguration. This test exists so that a later "fix" adding an
    equality check has to delete a test that says why not.
    """
    broker = load_broker_config(
        write(tmp_path, COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = 0")),
        env={},
    )
    control = load_control_config(write(tmp_path / "c", CONTROL_COMPLETE), env={})
    assert broker.audit_segment_bytes == 0
    assert control.audit_segment_bytes == 64 * 1024 * 1024


def test_a_negative_segment_bytes_is_a_config_error(tmp_path):
    text = COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = -1")
    with pytest.raises(
        ConfigError, match=re.escape("audit.segment_bytes must be zero or greater, got -1")
    ):
        load_broker_config(write(tmp_path, text), env={})
```

  Check the existing file for the real helper names (`write`, `COMPLETE`,
  `CONTROL_COMPLETE`, `_AUDIT_SECTION`) and match them exactly; the B2 section
  around line 573 is the template.

- [ ] **Step 2: the failing wiring tests.** Append to
  `tests/warden/test_key_split.py`, beside its B2 pair at line 674, and add
  `segment_bytes` to that file's `broker_config()` and `control_config()`
  helpers the way `durability` already is:

```python
# --- B3: the configured segment size must actually reach the log ------------


def test_the_broker_builds_its_audit_log_with_the_configured_segment_bytes(
    tmp_path, public_key
):
    """The step whose omission leaves [audit].segment_bytes parsed and never
    consumed -- a log that grows without bound while the config says
    otherwise. AuditLog.segment_bytes is public precisely so this needs no
    mock."""
    config = broker_config(tmp_path, public_key, segment_bytes=4096)
    components = build(config)
    assert components.audit.segment_bytes == 4096


def test_the_control_plane_builds_its_audit_log_with_the_configured_segment_bytes(
    tmp_path, private_key
):
    ...  # mirror the B2 test directly above, asserting captured["segment_bytes"]
```

- [ ] **Step 3: the failing renderer test.** Append to `tests/demo/test_cli.py`:

```python
def test_replay_describes_an_anchor_record(tmp_path):
    """A fourth action.type, same reason as tool_list, mcp_handshake and mint:
    without a branch the renderer falls through and prints `?()` for a record
    inside the same hash chain as real decisions."""
    from warden.cli.replay import _describe

    assert _describe(
        {
            "action": {"type": "anchor"},
            "target": {"kind": "segment", "previous": "audit-000008.jsonl"},
        }
    ) == "anchor(audit-000008.jsonl)"
```

- [ ] **Step 4: run all three and watch them fail.**

Run: `.venv/bin/pytest tests/warden/test_config_loader.py tests/warden/test_key_split.py tests/demo/test_cli.py -q 2>&1 | tail -15`
Expected: `AttributeError: 'BrokerConfig' object has no attribute
'audit_segment_bytes'`, and `assert '?()' == 'anchor(...)'`.

- [ ] **Step 5: the loader.** Import the constant beside B2's:

```python
from warden.broker.audit import DEFAULT_DURABILITY, DEFAULT_SEGMENT_BYTES, DURABILITY_LEVELS
```

  Add to `BrokerConfig`, under `audit_durability`:

```python
    # Where a segment closes; 0 disables rotation. Like audit_durability and
    # unlike audit_path, this one need NOT match control.toml's -- a
    # disagreement makes segment sizes irregular, because whichever writer
    # crosses its own threshold is the one that rotates, and irregular is not
    # wrong. See the B3 design, decision 14.
    audit_segment_bytes: int
```

  the same field with the same comment on `ControlConfig`, and in both
  constructors:

```python
        audit_segment_bytes=_positive(
            audit, "audit", "segment_bytes", DEFAULT_SEGMENT_BYTES, allow_zero=True
        ),
```

  `_positive` is the right helper and needs no change: it defaults a missing
  key, refuses a non-integer through `_integer`, and `allow_zero=True` is
  exactly "0 means never rotate".

- [ ] **Step 6: the wiring.** In `warden/broker/__main__.py` and
  `warden/broker/control_main.py`:

```python
        audit=AuditLog(
            config.audit_path,
            durability=config.audit_durability,
            segment_bytes=config.audit_segment_bytes,
        ),
```

- [ ] **Step 7: `_describe`'s fourth branch** in `warden/cli/replay.py`, after
  the `mint` branch:

```python
    if record["action"].get("type") == ANCHOR_ACTION_TYPE:
        # The record audit.py writes itself when a segment closes (B3). Fourth
        # branch, same reason as the three above -- without it this renders
        # `?()` inside the same hash chain as real decisions.
        #
        # It cannot reach the ✓/✗ column today: its task_id is "-" and this
        # renderer only ever sees records `warden replay` matched against a
        # task_id. What the CLI should say about segments is B4.
        return f"anchor({record.get('target', {}).get('previous', '?')})"
```

  with `ANCHOR_ACTION_TYPE` added to the existing `from warden.broker.audit
  import ...` line, sorted.

- [ ] **Step 8: `NarratedAudit`** in `demo/cli/explain.py`, beside its
  `records`/`verify_chain` pair:

```python
    def segments(self):
        # Forwarded although nothing in the narrated path calls it. These
        # wrappers forward hand-written SUBSETS of interfaces, and this file
        # exists because one of them silently lagged an interface that grew.
        return self._inner.segments()
```

- [ ] **Step 9: both TOMLs.** In `demo/scenario/warden.toml`'s `[audit]`, after
  `durability`:

```toml
# Where a segment closes, in bytes. At 64MiB (the default, written out here
# because a knob nobody can find is a knob nobody sets) a segment holds about
# 123,000 records. The active segment always keeps the `path` above; a closed
# one becomes a sibling named for the seq of its last record --
# /data/audit-000008.jsonl -- whose first record anchors to it by name and by
# hash, so the chain still verifies end to end. 0 disables rotation.
#
# Like `durability` and unlike `path`, this need NOT match control.toml's: the
# writer that crosses its own threshold is the one that rotates, so a
# disagreement makes segment sizes irregular rather than wrong.
segment_bytes = 67108864
```

  and the shorter note in `demo/scenario/control.toml`, matching how
  `durability` is written there.

- [ ] **Step 10: `docs/ROADMAP.md`.** Strike the B3 row, in the shape B2's row
  uses — what is now true, the measurement, and the alternative it beat. Then
  fix § B's exit paragraph, which currently says *"rotation is B3/B4 and is
  not"*; B4 is still outstanding, so say precisely which half landed. Read the
  whole paragraph before rewriting it: B2 found three stale claims in the audit
  paragraph because rewriting one forces you to read all of it.

- [ ] **Step 11: `docs/ARCHITECTURE.md:108`** — the row calls the log
  `/data/audit.jsonl`. It is now that file plus its closed segments.

- [ ] **Step 12: the gates, including the matrix.** This task touches
  `demo/scenario/*.toml`:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .          # run BEFORE assuming a config-only edit is clean
.venv/bin/mypy warden --ignore-missing-imports
opa test warden/policies/ demo/scenario/data.json
.venv/bin/warden-demo explain --quiet-why
.venv/bin/warden-demo explain --matrix --quiet-why    # ~1 min, must complete
```

- [ ] **Step 13: commit.**

---

## Task 3 — the mutation pass

**Files:** whichever tests the pass finds weak, plus the two open sections of
the design doc.

- [ ] **Step 1: commit first.** `git status` must be clean. `git checkout --`
  reverts the implementation too, and reverts nothing on an untracked file.

- [ ] **Step 2: write the harness** in the scratchpad. It must, for each
  mutation: assert the search string is **unique** in the target file; apply it;
  clear `__pycache__` (`find . -path ./.venv -prune -o -name '__pycache__'
  -type d -exec rm -rf {} +` — CPython invalidates on mtime in whole *seconds*
  and size, so a same-second equal-size revert reruns the mutant); run the
  named test; scan the output for **both** `^FAILED` and collection errors, and
  report `broken mutation` for the latter; revert; clear `__pycache__` again.

  A mutation that does not compile reddens nothing and is indistinguishable
  from a gap. A mutation string can also redden by collision. Read the failing
  test names out of pytest rather than trusting the row.

- [ ] **Step 3: run all 27 mutations** from the design's proof table. For each,
  record: did it redden, and did it redden **the test the row names**.

- [ ] **Step 4: for every row that did not redden**, decide which is wrong —
  the test or the row — and fix the test. A proof table is a list of intentions
  until each row has been made to fail.

- [ ] **Step 5: fill in the design doc's "What the mutation pass found"**,
  including anything it could *not* catch.

- [ ] **Step 6: all five gates, then commit.**

---

## Self-review of this plan against the spec

- **Coverage.** Decisions 1–6 and 17 are Task 1 steps 7–8; 7, 8 and 16 are step
  7; 9–13, 18 and 19 are step 6; 14 is Task 2 steps 5, 6 and 9; 15 is Task 2
  step 7. Proof-table rows 1–19 and 24–27 are Task 1 step 1; rows 20–22 are
  Task 2 steps 1–2; row 23 is Task 2 step 3. Every row has a step.
- **Names.** `DEFAULT_SEGMENT_BYTES`, `ANCHOR_ACTION_TYPE`, `segment_bytes`,
  `segments()`, `_closed_segment_name`, `_closed_segment_files`, `_rotate`,
  `_fsync_directory`, `_identity`, `_still_the_active_segment`, `_anchor_of`,
  `audit_segment_bytes` — used identically in the tests, the implementation and
  the config.
- **One deliberate gap.** Task 1 step 8 shows the new wrapper around the
  existing append body rather than reproducing that body: it is 40 lines of
  B2/B6-annotated code that must move **unchanged** except for indentation, and
  quoting it here invites a retype that silently drops a comment. `git diff -w`
  is the check that it only moved.
