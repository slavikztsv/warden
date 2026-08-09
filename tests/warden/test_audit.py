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

    Deliberately not AuditLog.records(), which spans segments: several B3 tests
    below are about which file a record landed in, and a helper that hid that
    would make them pass against the bug they name.
    """
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


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
        task_state={"data_classes_held": [], "rows_charged_so_far": 0},
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


def test_concurrent_appends_produce_an_intact_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    n = 25
    threads = [threading.Thread(target=lambda: _append(log)) for _ in range(n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    records = log.records()
    assert len(records) == n
    assert sorted(record["seq"] for record in records) == list(range(1, n + 1))
    assert log.verify_chain() == (True, None)


def test_injected_field_is_detected_as_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    _append(log)

    lines = path.read_text().splitlines()
    doctored = json.loads(lines[0])
    doctored["note"] = "approved by admin"
    lines[0] = json.dumps(doctored)
    path.write_text("\n".join(lines) + "\n")

    ok, bad_seq = AuditLog(path).verify_chain()
    assert ok is False
    assert bad_seq == 1


def test_appending_does_not_re_read_the_log(tmp_path):
    """B1. `_head()` used to read and JSON-parse the WHOLE file on every
    append -- inside the lock, which is what every concurrent caller queues
    on. Measured before the change: 0.76ms per append at 100 records, 8.0ms
    at 1000, 37.1ms at 4000, and 71.8s for 4000 appends.

    That cost is why this landed before the spine moved onto a threadpool.
    Offloading onto a lock whose cost grows without bound would have moved
    the ceiling rather than removed it.

    Asserted as a call count, not a duration: the property is "does not
    read", and a timing assertion would be flaky as well as weaker.

    B6 made this STRONGER rather than replacing it. B1 met the property with
    an in-memory cache, which bought the first append an exemption: that one
    read the whole file, once per process. The head now comes from the file's
    TAIL under the lock, so there is no cache to populate and no exemption to
    grant -- the count below starts at zero appends, not at one.
    """
    log = AuditLog(tmp_path / "audit.jsonl")

    reads = []
    real_records = log.records

    def counting_records():
        reads.append(1)
        return real_records()

    log.records = counting_records  # instance attribute shadows the method
    for _ in range(5):
        _append(log)

    assert reads == [], f"append re-read the log {len(reads)} times"

    del log.records
    assert log.verify_chain() == (True, None)
    # Five, not six: the priming append that used to warm the cache is gone.
    assert [record["seq"] for record in log.records()] == [1, 2, 3, 4, 5]


def test_a_failed_write_consumes_no_sequence_number(tmp_path):
    """A write that raised must leave the head where it was.

    Under B1 this was an ordering rule -- advance the cache AFTER the write,
    never before, or the chain breaks at the NEXT successful append, one call
    removed from the thing that caused it. B6 makes it true by construction
    instead: there is nothing to advance, because the head is whatever is
    actually on disk. The assertion is kept rather than deleted because the
    property is the same one, and a property that now holds for free is
    exactly the kind that quietly stops holding.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    first = _append(log)

    with patch.object(Path, "open", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            _append(log)

    second = _append(log)
    assert second["seq"] == 2, "the failed write consumed a sequence number"
    assert second["prev_hash"] == first["hash"]
    assert log.verify_chain() == (True, None)
    # And re-read from disk, so the assertion is about the file rather than
    # about the cache agreeing with itself.
    assert AuditLog(path).verify_chain() == (True, None)


def test_written_lines_are_key_sorted(tmp_path):
    """The file's bytes must not depend on dict insertion order.

    canonical_json already sorts for hashing; the write did not, so a target
    dict built in a different order changed the file while every hash still
    verified. That is a diff a reader reads as tampering and every check
    reads as clean.
    """
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(
        task_id="t",
        agent_id="a",
        purpose="p",
        # Deliberately reverse-alphabetical, so insertion order and sorted
        # order cannot coincide by accident.
        target={"kind": "db", "host": "", "estimated_rows": 3},
        action={"type": "tool_call", "tool": "x"},
        args_digest="sha256:d",
        decision="allow",
        rule="allow",
        task_state={"data_classes_held": [], "rows_charged_so_far": 0},
        policy_bundle_digest="sha256:b",
    )
    line = (tmp_path / "audit.jsonl").read_text().strip()
    keys = list(json.loads(line).keys())
    assert keys == sorted(keys), keys
    nested = list(json.loads(line)["target"].keys())
    assert nested == sorted(nested), nested


def test_a_written_record_has_exactly_these_fields(tmp_path):
    """The record body is an INTERFACE, and nothing was pinning its shape.

    Found by mutation while proving B6: adding a `writer` field to every
    record body passed all 809 tests. The frozen golden chain does not catch
    it -- that file is READ, never written -- and `verify_chain` hashes
    whatever keys a stored record happens to carry, precisely so an injected
    field cannot hide from it. Both behaviours are right; neither is a guard
    on what `append` produces.

    That matters now rather than in the abstract. The record shape is one of
    the three interfaces ROADMAP F3 says other people will depend on, and B7
    (audit the mint) is the next change that will want to add to it. This
    makes doing so a deliberate act with a test to update, not a silent one.

    Hardcoded on purpose. Deriving the expectation from `_BODY_FIELDS` would
    make a field added to both halves pass, which is the one thing this must
    not do.
    """
    log = AuditLog(tmp_path / "audit.jsonl")
    record = _append(log)
    assert sorted(record) == [
        "action",
        "agent_id",
        "args_digest",
        "decision",
        "hash",
        "policy_bundle_digest",
        "prev_hash",
        "purpose",
        "rule",
        "seq",
        "target",
        "task_id",
        "task_state",
        "ts",
    ]
    # And what is on DISK, not just what was returned -- they are different
    # dicts, and only one of them is the artifact anybody audits.
    written = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert sorted(written) == sorted(record)


# --------------------------------------------------------------------------
# B6. Multi-writer sequencing.
#
# Designed in docs/superpowers/specs/2026-08-06-p2b6-multi-writer-audit-design.md.
# Everything below exists because `seq` and `prev_hash` used to be allocated
# under a lock that only excluded threads in ONE process.


# A FRESH INTERPRETER, not a fork. Two reasons, both load-bearing:
# multiprocessing's fork start method inherits the parent's memory, which is
# exactly the state a cache-based bug lives in and therefore the more
# forgiving test; and forking a multi-threaded pytest process is a documented
# deadlock hazard that would make the audit suite's most important test flaky.
# This is also how a second broker actually arrives -- as its own process.
_APPEND_SCRIPT = """
import sys
from warden.broker.audit import AuditLog

log = AuditLog(sys.argv[1])
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


def test_two_processes_appending_produce_one_intact_chain(tmp_path):
    """B6, the load-bearing one.

    Measured against the code this replaces -- four processes, 200 appends
    each: 800 records written, 451 distinct seqs, verify_chain BROKEN at
    seq 52. Every write succeeded; only the chain was destroyed, which is
    what makes this the failure mode the one artifact that must be
    trustworthy cannot have.

    Processes rather than threads ON PURPOSE: the threading.Lock already
    excluded threads, so a thread-based version of this passed against the
    very bug it exists to catch.
    """
    path = tmp_path / "audit.jsonl"
    procs, per_proc = 4, 40
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", _APPEND_SCRIPT, str(path), str(per_proc)],
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(procs)
    ]
    # Started before any is waited on, so they genuinely contend.
    for worker in workers:
        _, stderr = worker.communicate(timeout=120)
        assert worker.returncode == 0, stderr

    log = AuditLog(path)
    records = log.records()
    total = procs * per_proc
    assert len(records) == total
    # Dense 1..N, in file order. Not `sorted(...)`: the seqs must come out in
    # the order they were written, because prev_hash links them in that order
    # and a chain that verifies out of order is not a chain.
    assert [record["seq"] for record in records] == list(range(1, total + 1))
    assert log.verify_chain() == (True, None)


def test_the_head_is_read_from_the_file_not_from_memory(tmp_path):
    """Two AuditLog objects, one file, alternating appends.

    This is the test that fails the moment a head cache is reinstated. It is
    not the same as reopening the log (which the test above it covers): here
    BOTH objects stay alive and interleave, so an object that remembers where
    it left off is wrong by the time it writes again. Spiked against a
    half-fix -- a tail reader interleaved with a cache holder still reported
    BROKEN at seq 3.
    """
    path = tmp_path / "audit.jsonl"
    first, second = AuditLog(path), AuditLog(path)
    for _ in range(3):
        _append(first)
        _append(second)

    log = AuditLog(path)
    assert [record["seq"] for record in log.records()] == [1, 2, 3, 4, 5, 6]
    assert log.verify_chain() == (True, None)


def test_a_record_wider_than_the_tail_window_is_still_found(tmp_path):
    """The tail window doubles; it is not fixed.

    A record is not fixed-width and its width is not ours to choose:
    broker/proxy.py takes `authority` off the CONNECT request line -- bounded
    only by asyncio's 64KiB header limit -- and puts it straight into the
    record's `target`. So the oversized record is exactly the one a PROBE
    produces, and a fixed window would fail on precisely that.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    huge = _append(log, target={"kind": "http", "host": "h" * 20_000})
    after = _append(log)

    assert after["prev_hash"] == huge["hash"], "the head was not found past the window"
    assert after["seq"] == 3
    assert AuditLog(path).verify_chain() == (True, None)


def test_a_torn_trailing_line_refuses_the_append(tmp_path):
    """A writer killed mid-write leaves a partial line. Fail closed.

    Appending after it would build a chain that can never verify. The refusal
    is an OSError so it lands in the spine's existing AUDIT_UNAVAILABLE
    handling, and the partial line is left exactly where it is -- an audit log
    that silently deletes a byte it did not like is not tamper-evident.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq": 2, "ts": "2026-08-06T00')  # killed mid-write

    before = path.read_bytes()
    with pytest.raises(OSError):
        _append(log)
    assert path.read_bytes() == before, "the log was repaired instead of refused"


# Takes the lock, says so, then sits on it. The "ready" line is what makes
# this deterministic rather than a sleep race: the parent does not attempt its
# append until the lock is provably held.
_HOLD_SCRIPT = """
import fcntl, sys, time

handle = open(sys.argv[1], "a+b")
fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
sys.stdout.write("ready\\n")
sys.stdout.flush()
time.sleep(float(sys.argv[2]))
"""


def test_a_held_lock_times_out_as_an_oserror(tmp_path):
    """A wedged writer must not take every worker thread with it.

    A6 put every append on a 16-thread pool the broker owns, so an unbounded
    flock means one stuck writer stops the broker serving with nothing
    anywhere saying why. Bounded, and OSError rather than a bare Exception,
    because that is the type the spine already turns into a recorded refusal.
    """
    path = tmp_path / "audit.jsonl"
    path.touch()
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLD_SCRIPT, str(path), "30"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline() == "ready\n", "the holder never took the lock"
        log = AuditLog(path, lock_timeout=0.2)
        started = time.monotonic()
        with pytest.raises(OSError):
            _append(log)
        # Bounded by the timeout, not by the holder. The point is that it gave
        # up while the lock was STILL held: a test that only proved it
        # eventually returned would pass against an unbounded blocking flock.
        assert time.monotonic() - started < 3.0
    finally:
        holder.kill()
        holder.wait(timeout=30)


# --- B2: durability -------------------------------------------------------
#
# Designed in docs/superpowers/specs/2026-08-06-p2b2-audit-durability-design.md.
# These assert the SYSCALL, not the physics: there is no way to power-cycle a
# host from pytest. What they pin is that the log's own descriptor is fsynced,
# on the append, before append() returns -- and that the parent directory is
# fsynced on the one append that creates the file.


def _fsync_spy(seen: list[int]):
    """Records the inode behind every fsynced fd, then really fsyncs."""
    real = os.fsync

    def spy(fd: int) -> None:
        seen.append(os.fstat(fd).st_ino)
        real(fd)

    return spy


def test_an_append_fsyncs_the_log_before_returning(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)  # record 1 also fsyncs the directory; keep this append clean
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        _append(log)
    assert os.stat(path).st_ino in seen


def test_flush_durability_does_not_fsync(tmp_path):
    """The level that shipped before B2, kept reachable and named."""
    log = AuditLog(tmp_path / "audit.jsonl", durability="flush")
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        record = _append(log)
    assert seen == []
    # Still a real, readable, chained record -- "flush" weakens durability and
    # nothing else.
    assert record["seq"] == 1
    assert log.records() == [record]
    assert log.verify_chain() == (True, None)


def test_the_first_record_also_fsyncs_the_directory(tmp_path):
    """fsync on the file makes its CONTENTS durable, not its directory entry.

    Without this, a power loss shortly after a log is first created loses the
    whole file -- including record 1, whose append() already returned and whose
    action therefore went ahead.
    """
    path = tmp_path / "audit.jsonl"
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        _append(AuditLog(path))
    assert os.stat(path).st_ino in seen
    assert os.stat(tmp_path).st_ino in seen


def test_later_records_do_not_fsync_the_directory(tmp_path):
    """Once per log, on the append that creates it -- not 1.4ms on every one."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        _append(log)
    assert os.stat(tmp_path).st_ino not in seen


def test_an_unrecognised_durability_is_refused_by_the_constructor(tmp_path):
    """Never a fallback, in EITHER direction. Falling back to "flush" silently
    weakens the log; falling back to "fsync" silently ignores what was written.
    """
    with pytest.raises(
        ValueError,
        match=r"audit durability must be one of \('fsync', 'flush'\), got 'fsyncc'",
    ):
        AuditLog(tmp_path / "audit.jsonl", durability="fsyncc")


def test_a_failed_fsync_refuses_the_append_as_an_oserror(tmp_path):
    """Into the machinery that already exists: spine.py catches OSError at all
    four of its _append sites and control.py catches it around record_mint, so
    a failing disk becomes a 503 with nothing executed.

    The written line STAYS. This log does not delete bytes it did not like --
    the same rule _head_from_tail states for a torn trailing line. The
    consequence is stated rather than fixed: the file over-reports by one
    record, and the enforcement failed in the safe direction.

    PRE-SEEDED, and that is load-bearing rather than tidiness. Written against
    a fresh log this test passed with the file fsync's failure SWALLOWED --
    the exact bug it names -- because a fresh log makes the append under test
    record 1, which also fsyncs the parent directory, and the patched fsync
    raised there instead. The mutation pass caught it; the assertion did not.
    One existing record makes this record 2, so the file fsync is the only one
    that fires.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)

    def failing(fd: int) -> None:
        raise OSError("input/output error")

    with patch.object(os, "fsync", failing):
        with pytest.raises(OSError, match="input/output error"):
            _append(log)
    assert len(log.records()) == 2


_LOCK_PROBE = """
import fcntl, sys
handle = open(sys.argv[1], "a+b")
try:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("held")
else:
    print("free")
"""


def test_the_fsync_happens_while_the_lock_is_still_held(tmp_path):
    """The load-bearing ordering, and the reason the lock hold went 16x.

    Releasing the flock before the fsync would let writer B read the tail,
    chain onto record N and have its own append() return while N is still only
    in the page cache. The chain is CONTENT-linked, so losing N while keeping
    N+1 leaves a prev_hash pointing at a record nobody has -- unrepairable by
    replay, backup or anything else, and the precise failure B6 rejected the
    Redis-CAS design for.

    A fresh interpreter, never multiprocessing: tests/ has no __init__.py and
    pytest.ini sets --import-mode=importlib, so a spawn child cannot re-import
    the test module, and forking a multi-threaded pytest process is a
    documented deadlock hazard.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)  # so the append under test fires exactly one fsync

    seen: list[str] = []
    real = os.fsync

    def probing(fd: int) -> None:
        seen.append(
            subprocess.run(
                [sys.executable, "-c", _LOCK_PROBE, str(path)],
                capture_output=True,
                text=True,
                timeout=120,
            ).stdout.strip()
        )
        real(fd)

    with patch.object(os, "fsync", probing):
        _append(log)

    assert seen == ["held"]


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
    """The closed segment is named for the seq of its LAST record -- which the
    tail read already has in hand, so naming costs no extra read."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    written = _fill_to_threshold(log, path, 4096)
    last_before = written[-1]["seq"]

    _append(log)

    closed = tmp_path / f"audit-{last_before:06d}.jsonl"
    assert closed.exists(), sorted(p.name for p in tmp_path.iterdir())
    assert [r["seq"] for r in json_lines(closed)] == list(range(1, last_before + 1))


def test_the_new_segment_holds_its_anchor_before_it_is_the_active_segment(tmp_path):
    """The whole of B3.

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
    """Dense seqs across every segment, and a chain that verifies from genesis
    -- read by a SECOND AuditLog, so the assertion is about the files and not
    about one object agreeing with itself."""
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
    """The name is what the anchor adds: prev_hash already carries the previous
    segment's head hash. Without the name, an operator who archives the oldest
    segment leaves a log whose first record links to a hash nobody can produce
    -- indistinguishable from tampering."""
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
    """One record shape, on B7's decision 9: the mint reused the thirteen body
    fields so AuditLog needed no new field, and so does this.

    Compared against a real decision record rather than a hardcoded list, so a
    field added to the record shape without being added to the anchor fails
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
    assert anchor["purpose"] == "audit-segment-rotation"
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
    """The load-bearing one, and B6's test with rotation switched on.

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
    """The staleness check, deterministically -- the process test above is a
    race by nature.

    Rotates the log from inside `_acquire` and BEFORE the real lock is taken,
    which is the only interleaving that can actually happen: a rotating writer
    holds the flock while it rotates, so a writer that opened the file first
    necessarily acquires the lock AFTERWARDS -- on a descriptor that is already
    stale. Rotating after `real_acquire` instead just deadlocks the rotator
    against the lock this call is holding (two descriptors in one process do
    exclude each other), which is how this test was first written and why it
    took five seconds to fail.

    Without the check the record lands in the closed segment, with a prev_hash
    the new segment's anchor also claims: two records with one predecessor,
    which is the fork.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    written = _fill_to_threshold(log, path, 4096)
    rotator = AuditLog(path, segment_bytes=4096)

    real_acquire = audit_module._acquire
    rotations = []

    def rotate_then_acquire(handle, timeout):
        # Marked BEFORE rotating, not after: the rotator's own append goes
        # through this same patched function, so a guard set afterwards recurses
        # forever.
        if not rotations:
            rotations.append(None)
            rotations[0] = _append(rotator)
        real_acquire(handle, timeout)

    with patch.object(audit_module, "_acquire", rotate_then_acquire):
        record = _append(log)

    # The rotator wrote two records: the new segment's anchor, and its own.
    assert rotations[0]["seq"] == written[-1]["seq"] + 2
    assert record["seq"] == rotations[0]["seq"] + 1
    closed = tmp_path / f"audit-{written[-1]['seq']:06d}.jsonl"
    assert json_lines(closed)[-1]["seq"] == written[-1]["seq"], (
        "a record was appended into the closed segment"
    )
    assert AuditLog(path, segment_bytes=4096).verify_chain() == (True, None)


def test_endless_rotation_gives_up_within_one_lock_timeout(tmp_path):
    """Bounded, and bounded by ONE lock_timeout for the whole call rather than
    one per attempt: giving each attempt a fresh five seconds would let a
    retrying append hold a threadpool thread for a multiple of the constant
    whose own comment says one wedged writer must not wedge every worker.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, durability="flush", segment_bytes=4096, lock_timeout=0.3)
    _fill_to_threshold(log, path, 4096)
    rotator = AuditLog(path, durability="flush", segment_bytes=1)

    real_acquire = audit_module._acquire
    inside = []

    def rotate_then_acquire(handle, timeout):
        # Before the lock, and re-entrancy-guarded, for the reasons the test
        # above states. segment_bytes=1 makes every rotator append rotate, so
        # this writer is rotated out on every attempt it makes.
        if not inside:
            inside.append(None)
            try:
                _append(rotator)
            finally:
                inside.clear()
        real_acquire(handle, timeout)

    started = time.monotonic()
    with patch.object(audit_module, "_acquire", rotate_then_acquire):
        with pytest.raises(OSError, match="was rotated out from under this writer"):
            _append(log)
    assert time.monotonic() - started < 3.0


def test_each_retry_gets_what_is_left_of_the_one_lock_timeout(tmp_path):
    """Added by the mutation pass, which is what found it missing.

    `test_endless_rotation_gives_up_within_one_lock_timeout` above pins that a
    writer rotated out forever gives up, and gives up as an OSError -- but it
    does NOT pin the budget arithmetic. Passing `self._lock_timeout` to every
    attempt instead of what is left of it changed nothing that test could see,
    because nothing in it contends for the lock, so `_acquire` returns
    immediately whatever timeout it is handed. Measured: that mutation reddened
    nothing.

    What it would break is real: a two-attempt append could hold a pool thread
    for twice the constant whose own comment says one wedged writer must not
    wedge every worker. So this reads the budget `_acquire` is actually given,
    and forces exactly one retry through the staleness check rather than through
    a real rotation -- the shortest path to two attempts.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, durability="flush", segment_bytes=0, lock_timeout=5.0)
    _append(log)

    real_check = audit_module._still_the_active_segment
    real_acquire = audit_module._acquire
    budgets: list[float] = []
    checks: list[None] = []

    def stale_exactly_once(handle, target):
        checks.append(None)
        return real_check(handle, target) if len(checks) > 1 else False

    def recording_acquire(handle, timeout):
        budgets.append(timeout)
        # Burn a measurable slice of the budget, so "what is left" and "the whole
        # thing" cannot come out equal to the resolution of the clock.
        time.sleep(0.01)
        real_acquire(handle, timeout)

    with patch.object(audit_module, "_still_the_active_segment", stale_exactly_once):
        with patch.object(audit_module, "_acquire", recording_acquire):
            record = _append(log)

    assert record["seq"] == 2
    assert len(budgets) == 2, budgets
    assert budgets[0] <= 5.0
    assert budgets[1] < budgets[0], (
        "the second attempt was given a fresh lock_timeout instead of the "
        f"remainder of the first: {budgets}"
    )


def test_a_threshold_below_one_record_still_makes_progress(tmp_path):
    """At most one rotation per append() call, so any threshold terminates.
    Without the flag, a threshold below one record makes every append rotate,
    reopen, find the new segment also over the threshold, and rotate again
    until the deadline -- so appends FAIL rather than merely producing tiny
    segments."""
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
    """The SECOND directory fsync is durability -- the record is written into
    the new segment after the replace, so a replace that is not durable leaves
    it in a nameless inode, which is B2's failure one level up.

    The FIRST one is ordering, and it is the one that is easy to leave out. The
    link and the replace are both unfsynced directory metadata and POSIX orders
    neither; a filesystem free to make the replace durable while the link is
    not would leave the closing segment with NO NAME and its records
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

    # The staging file, the directory before the replace, the directory after
    # it, then the record's own file.
    assert seen == ["file", "dir", "dir", "file"]


def test_flush_durability_does_not_fsync_a_rotation(tmp_path):
    """"flush" promises the page cache, not the device; spending 3.1ms per
    rotation to half-honour a promise the operator declined is how a config key
    comes to mean two things."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, durability="flush", segment_bytes=4096)
    _fill_to_threshold(log, path, 4096)

    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        _append(log)
    assert seen == []
    assert AuditLog(path, segment_bytes=4096).verify_chain() == (True, None)


def test_a_crash_between_link_and_replace_is_readable_and_completes(tmp_path):
    """The rotation is not atomic as a whole, and the window between the link
    and the replace leaves the closing segment with TWO names, one of which is
    still the active one.

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

    # The next append finds the segment still over the threshold and rotates,
    # which COMPLETES the interrupted one: two more records, the anchor and the
    # append's own, and the duplicate name is now a real closed segment.
    record = _append(log)
    after = AuditLog(path, segment_bytes=4096)
    assert record["seq"] == len(written) + 2
    assert [r["seq"] for r in after.records()] == list(range(1, len(written) + 3))
    assert after.verify_chain() == (True, None)
    assert after.segments() == [closed, path]


def test_a_foreign_file_at_the_closed_name_refuses_the_rotation(tmp_path):
    """The same-inode branch above must not become a blanket "FileExistsError
    means carry on", or a file that is not this log gets absorbed into the
    chain as a segment."""
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
    """An operator deleting the active file while segments exist is the spiked
    fork arriving by another route: "a+b" recreates it, the tail read answers
    genesis, and the log acquires a second chain that verifies."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    assert len(AuditLog(path, segment_bytes=4096).segments()) > 1
    path.unlink()

    with pytest.raises(OSError, match="refusing to start a second chain at genesis"):
        _append(log)


def test_a_newline_only_active_segment_refuses_the_append(tmp_path):
    """Gated on the HEAD reading as genesis, not on st_size == 0:
    _head_from_tail documents a second way to read as genesis -- a file of
    nothing but newlines -- so a size test leaves a hole in exactly the place
    the code it guards already has a special case."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    path.write_bytes(b"\n\n")

    with pytest.raises(OSError, match="refusing to start a second chain at genesis"):
        _append(log)


def test_an_absent_predecessor_refuses_the_read(tmp_path):
    """Pruning an audit log is a real operator need and B3 does not serve it.
    Refusing names both files; verifying the available suffix instead would
    report `chain BROKEN at seq N` -- calling a deliberate operator action
    tampering."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    segments = AuditLog(path, segment_bytes=4096).segments()
    oldest, namer = segments[0], segments[1]
    oldest.unlink()

    with pytest.raises(
        OSError,
        match=f"audit segment {oldest.name} is missing, named by {namer.name}",
    ):
        AuditLog(path, segment_bytes=4096).records()


def test_an_anchor_naming_a_path_refuses_the_read(tmp_path):
    """A log is precisely the artifact that may have been hand-edited, so a
    crafted anchor must not become a file this code opens."""
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
    """Every closed-segment-shaped file in the directory must be reachable from
    the active segment's anchors. This is what catches a log that forked: the
    fork's segments are on disk, and nothing names them."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    (tmp_path / "audit-999999.jsonl").write_text("{}\n")

    with pytest.raises(
        OSError,
        match=r"segment files nothing in the chain names: \['audit-999999.jsonl'\]",
    ):
        AuditLog(path, segment_bytes=4096).records()


def test_an_anchor_cycle_refuses_the_read(tmp_path):
    """A hand-edited pair of anchors naming each other is an infinite walk, and
    an audit tool that hangs is an audit tool that gets skipped."""
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
    """Zero migration: an unrotated single-file log IS segment 0, whose first
    record links to genesis and which carries no anchor."""
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
    """[audit].path is a string an operator writes; nothing makes it end in
    .jsonl."""
    path = tmp_path / "auditlog"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)

    reader = AuditLog(path, segment_bytes=4096)
    assert len(reader.segments()) > 1
    assert reader.segments()[0].name.startswith("auditlog-0")
    assert reader.verify_chain() == (True, None)


def test_a_path_with_glob_metacharacters_still_finds_its_segments(tmp_path):
    """Path.glob interprets its argument as a PATTERN, so a stem containing
    [ ] * or ? would make the orphan scan search a different set of names than
    the segment pattern accepts -- and the mismatch empties the guard rather
    than tripping it."""
    path = tmp_path / "audit[1].jsonl"
    log = AuditLog(path, segment_bytes=4096)
    for _ in range(30):
        _append(log)
    assert len(AuditLog(path, segment_bytes=4096).segments()) > 1
    path.unlink()

    with pytest.raises(OSError, match="refusing to start a second chain at genesis"):
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
    """On by default: a deployment that reaches 64MiB has ~123,000 records and
    a real operational problem, and one that never reaches it is unaffected."""
    assert DEFAULT_SEGMENT_BYTES == 64 * 1024 * 1024
    assert AuditLog(tmp_path / "audit.jsonl").segment_bytes == DEFAULT_SEGMENT_BYTES


def test_a_negative_segment_bytes_is_refused_by_the_constructor(tmp_path):
    """Same discipline as `durability`: never a silent fallback."""
    with pytest.raises(
        ValueError, match=r"audit segment_bytes must be a non-negative integer, got -1"
    ):
        AuditLog(tmp_path / "audit.jsonl", segment_bytes=-1)
