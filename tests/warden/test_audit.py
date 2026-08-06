import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from warden.broker.audit import GENESIS_HASH, AuditLog, canonical_json


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
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)

    def failing(fd: int) -> None:
        raise OSError("input/output error")

    with patch.object(os, "fsync", failing):
        with pytest.raises(OSError, match="input/output error"):
            _append(log)
    assert len(log.records()) == 1


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
