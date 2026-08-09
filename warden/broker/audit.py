"""Append-only, hash-chained decision log.

Tamper-evident, not tamper-proof: modifying a record breaks the chain and
becomes detectable, but nothing here prevents the edit.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

# The first thing this module has ever imported from inside `warden`, and the
# right direction: record_fields exists because two processes writing one chain
# "must agree on what a field's value means or the chain is one file containing
# two vocabularies", and B3's `_rotate` below makes THIS module a third writer.
# It imports nothing but the standard library, and both processes that hold an
# AuditLog already import it, so this costs no module anywhere.
from warden.broker.record_fields import empty_task_state

GENESIS_HASH = "0" * 64

# How long a writer waits for another writer's lock before giving up. Bounded
# rather than infinite because A6 put every append on a 16-thread pool the
# broker owns: an unbounded flock means one wedged writer wedges every worker
# and the broker stops serving with nothing anywhere saying why. Five seconds
# is far past any honest append -- one measures ~60us -- so reaching it means
# something is wrong, and the OSError below says so.
#
# A constructor default rather than a config knob, deliberately, and unlike
# A6's `worker_threads`: that one was invisible AND machine-dependent
# (asyncio's min(32, cpu_count + 4)), which is not a limit this product gets
# to leave undocumented. This one is a fixed constant in a single place.
#
# B2 arrived, added `[audit].durability`, and deliberately did NOT bring this
# with it. Bundling would have changed the config surface once instead of
# twice -- a real argument, and a "while we're here" one. The substantive test
# is whether anything now NEEDS the timeout configurable, and nothing does:
# five seconds was ~47,000x an append before B2 and is ~2,900x one after, and
# the worst contention B2 creates -- sixteen threads at ~1.7ms each, ~27ms --
# is still two orders of magnitude inside it. Adding a knob nobody needs to
# justify a knob somebody does is backwards.
_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_POLL_SECONDS = 0.005

# Where the tail read starts. It DOUBLES from here rather than being fixed,
# because a record is not fixed-width and its width is not ours to choose:
# broker/proxy.py takes `authority` straight off the CONNECT request line --
# bounded only by asyncio's 64KiB header limit -- and puts it in the record's
# `target`. A typical record is 682 bytes; one with a long host reached 8665.
# A fixed window finds no line boundary inside a record larger than itself,
# so it would fail on exactly the record a probe produces.
_TAIL_WINDOW_BYTES = 4096

# Where a segment closes, in bytes of the active segment, checked BEFORE the
# record that would cross it -- so a closed segment is at least this and at most
# this plus one record.
#
# ON by default, and that is a different kind of default from B2's: B2 CHANGED
# what an existing deployment does (16x slower appends), where this only starts
# doing something once a log reaches 64MiB. At the 547 bytes a record measures
# here that is ~123,000 records, at which point one file is a real operational
# problem -- no editor opens it, records() loads it whole into memory, and it
# cannot be archived in parts. A deployment that never gets there is untouched,
# which is every test in this suite and the demo's eight records.
#
# 64MiB and not 16 (33 segments per million records) or 256 (2): ROADMAP § B's
# exit is a million-record log that VERIFIES ACROSS ROTATION, and ~8 segments is
# the granularity that actually exercises that.
#
# 0 disables rotation entirely, which is exactly what shipped before B3. Not a
# separate flag: the loader's `_positive(..., allow_zero=True)` already means
# this, and one key cannot then disagree with another.
DEFAULT_SEGMENT_BYTES = 64 * 1024 * 1024

# The `action.type` of the record that opens every segment after the first.
# Named once because two files write or read it -- this one and
# warden/cli/replay.py -- and a second spelling would be a second vocabulary.
ANCHOR_ACTION_TYPE = "anchor"

# The two durability levels, and what each promises.
#
#   "fsync" -- the record is on STABLE STORAGE before append() returns. It
#     survives the host losing power, which is what makes README's "write the
#     decision down, BEFORE anything happens" true rather than nearly true.
#   "flush" -- the record is in the kernel's page cache before append()
#     returns. It survives this process being killed, not the host. This is
#     what shipped before B2, kept reachable and named.
#
# Named for the SYSCALL rather than for a promise ("safe"/"fast"): an operator
# choosing a level is choosing what survives what, and calling the other one
# "unsafe" would overstate it -- page-cache durability is a real property, and
# it is what this system shipped with until now.
#
# Two levels, not three. `fdatasync` is the usual cheaper `fsync`, and it is
# measured indistinguishable here -- 1687us against 1649us, inside the noise --
# because an append CHANGES THE FILE SIZE, so the metadata flush it exists to
# skip happens anyway. A level that costs a decision and buys nothing
# measurable is worse than no level.
DURABILITY_LEVELS = ("fsync", "flush")
DEFAULT_DURABILITY = "fsync"

# Field order is fixed so the hash is reproducible across processes.
_BODY_FIELDS = (
    "seq",
    "ts",
    "task_id",
    "agent_id",
    "purpose",
    "action",
    "target",
    "args_digest",
    "decision",
    "rule",
    "task_state",
    "policy_bundle_digest",
    "prev_hash",
)


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def record_hash(body: dict) -> str:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def _acquire(handle: BinaryIO, timeout: float) -> None:
    """Take an exclusive lock on the open log, or raise.

    `LOCK_NB` in a spin against a deadline rather than a blocking `LOCK_EX`,
    so a wedged writer cannot take every worker thread down with it. Not
    SIGALRM: that is not usable from a threadpool worker at all.

    The failure is an OSError on purpose. The spine's `except OSError` around
    every append, its AUDIT_UNAVAILABLE_* outcomes, and broker/proxy.py's
    best-effort branch already exist and already do the right thing, so a busy
    log becomes a RECORDED REFUSAL rather than a hang. Same reasoning that made
    TaskStateUnavailable an OSError in A2, and the same handlers downstream.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            # Deliberately checked AFTER an attempt, so timeout=0 still tries
            # once. Any other OSError (a bad descriptor, a filesystem with no
            # lock support) propagates untouched -- those are not contention.
            if time.monotonic() >= deadline:
                raise OSError(
                    f"audit log {getattr(handle, 'name', '?')} is held by another "
                    f"writer: gave up after {timeout}s"
                ) from None
            time.sleep(_LOCK_POLL_SECONDS)


def _head_from_tail(handle: BinaryIO) -> tuple[int, str]:
    """The (seq, hash) the next record links to, read from the file's END.

    Called under the lock, on an open descriptor, so the tail it finds cannot
    stop being the tail before the caller writes.

    This is what replaces B1's in-memory cache. B1's goal -- never re-parse the
    whole log to append one record -- is met more completely here, since this
    never parses the whole file even once; what B1 got wrong was the mechanism,
    because a cached head is a claim about who else is writing. Measured warm:
    ~12us more per ~60us append than the cache, flat at 100, 1000 and 4000
    records, against 37.1ms at 4000 before B1.
    """
    size = os.fstat(handle.fileno()).st_size
    if size == 0:
        return 0, GENESIS_HASH
    window = _TAIL_WINDOW_BYTES
    while True:
        start = max(0, size - window)
        handle.seek(start)
        # rstrip THEN rfind, and rfind rather than find. The window's last
        # newline is the one ending the second-to-last record; the first one it
        # happens to contain may be the trailing newline of the only record in
        # view, and cutting there leaves an empty buffer. The spike wrote it
        # the wrong way round first.
        blob = handle.read().rstrip(b"\n")
        cut = blob.rfind(b"\n")
        if cut != -1:
            blob = blob[cut + 1:]
            break
        if start == 0:
            break
        window *= 2
    if not blob:
        # A file of nothing but newlines. records() reads that as zero records,
        # so the head must be genesis here too -- two answers to "how long is
        # this log" is the one disagreement this file cannot have.
        return 0, GENESIS_HASH
    try:
        last = json.loads(blob)
        return last["seq"], last["hash"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        # A process killed mid-write leaves a partial final line. Appending
        # after it would build a chain that can never verify, so this refuses
        # -- as an OSError, into the handlers above.
        #
        # It does NOT truncate the partial line and carry on. An audit log that
        # silently deletes a byte it did not like is not tamper-evident, and
        # "a writer died here" versus "someone edited this" is not a
        # distinction this file gets to make on its own. warden verify-chain
        # already reports the same corruption the same way.
        raise OSError(f"audit log tail is not a complete record: {exc}") from exc


def _identity(path: Path) -> tuple[int, int]:
    """WHICH FILE a name refers to, rather than which name.

    Rotation deliberately gives the closing segment two names for a moment (see
    AuditLog._rotate), and a crash in that window leaves them both. Every "is
    this the same file" question in this module therefore has to be asked about
    the inode: a draft that compared resolved paths reported `segment files
    nothing in the chain names` for a log that was entirely fine, and left it
    unreadable until the next rotation -- 64MiB of writes later.
    """
    info = os.stat(path)
    return info.st_dev, info.st_ino


def _still_the_active_segment(handle: BinaryIO, path: Path) -> bool:
    """Whether the locked descriptor is the file `path` names RIGHT NOW.

    This is B6 for a log that rotates. A writer opens `path`, then spins for the
    flock; another writer holding that lock rotates; and the first writer now
    holds a descriptor on a segment that has been CLOSED. Its size is still over
    the threshold, so it does not merely append into a closed file -- it tries to
    ROTATE it, and produces a second, divergent lineage of segments.

    Measured with this check removed: four processes, 40 appends each, a 4KiB
    segment, three runs -- 3 of 4 writers dead every run, 35 to 75 of 160 appends
    returning at all, and what survived was either a chain BROKEN at seq 33 or a
    log that refuses to be read at all.

    A missing name counts as rotated away: reopening recreates it, and the
    genesis guard in `append` is what then refuses to start a second chain.
    """
    held = os.fstat(handle.fileno())
    try:
        named = os.stat(path)
    except FileNotFoundError:
        return False
    return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)


def _anchor_of(path: Path) -> dict | None:
    """A segment's anchor record, or None if it does not begin with one.

    `readline` rather than the tail read's doubling window: reading FORWARD to
    the first newline needs no window at all, whatever the record's width.

    Every "not an anchor" answer here is deliberately quiet, including a first
    line that is not JSON at all. This function answers one question -- what does
    this segment follow -- and `verify_chain` is what reports a corrupt record.
    A first record that is the log's own genesis record is the ordinary answer,
    not an error: that is what segment 0 looks like, and what every log written
    before B3 looks like.
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


class AuditLog:
    def __init__(
        self,
        path: Path,
        *,
        lock_timeout: float = _LOCK_TIMEOUT_SECONDS,
        durability: str = DEFAULT_DURABILITY,
        segment_bytes: int = DEFAULT_SEGMENT_BYTES,
    ) -> None:
        if durability not in DURABILITY_LEVELS:
            # Never a fallback, in EITHER direction. Falling back to "flush"
            # silently weakens the log, which is the failure config/schema.py's
            # parse_tool_schema exists to prevent; falling back to "fsync"
            # silently ignores what a caller wrote, which is how a deployment
            # acquires a throughput profile nobody chose.
            raise ValueError(
                f"audit durability must be one of {DURABILITY_LEVELS}, "
                f"got {durability!r}"
            )
        if not isinstance(segment_bytes, int) or segment_bytes < 0:
            # Never a silent fallback, exactly as `durability` above. A
            # threshold this object quietly ignored would be a deployment whose
            # log grows without bound while its config says otherwise.
            raise ValueError(
                f"audit segment_bytes must be a non-negative integer, got {segment_bytes!r}"
            )
        self.path = Path(path)
        # PUBLIC, alongside `path`: broker/__main__.py's build() returns its
        # BrokerComponents, so a test can assert that the configured level
        # actually reached the log rather than mocking the constructor call.
        self.durability = durability
        # Public for the same reason, and additionally because B4 is about
        # teaching the CLI what a segmented log is.
        self.segment_bytes = segment_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The IN-PROCESS half of the exclusion. `append` also takes an flock on
        # the file itself, which would be sufficient on its own -- two file
        # descriptors in one process do exclude each other -- but in-process
        # contention would then burn the flock spin's 5ms sleep budget, turning
        # a cheap uncontended mutex into a coarse poll. Two threads in one
        # broker are the common case; two brokers are the case flock is for.
        #
        # One order, always: this lock, then the flock, then the tail read,
        # then the write. A single pair taken in a single order, so no deadlock
        # is constructible.
        self._lock = threading.Lock()
        self._lock_timeout = lock_timeout

    # This constructor deliberately reads NOTHING. `warden verify-chain` exists
    # to be pointed at a CORRUPT log and report "chain BROKEN: malformed
    # record" -- and warden/cli/replay.py constructs this object BEFORE the
    # guard that produces that verdict, so a constructor that parsed the file
    # would make the one tool whose whole job is inspecting broken chains
    # traceback instead of reporting one. B1 satisfied that by populating its
    # head cache lazily; with no cache to populate it now holds by
    # construction, which is the better version of the same property.

    def _closed_segment_name(self, last_seq: int) -> str:
        """`audit.jsonl` closing at seq 8 becomes `audit-000008.jsonl`.

        Named for the seq of its LAST record, which the tail read already has in
        hand at rotation time, so naming costs no extra read. Unique by
        construction, because seqs are. Past 999,999 it grows a seventh digit and
        stops sorting lexically, which costs nothing: order comes from the
        anchors, not from the names.
        """
        return f"{self.path.stem}-{last_seq:06d}{self.path.suffix}"

    def _closed_segment_files(self) -> list[Path]:
        """Every sibling shaped like a closed segment of THIS log.

        `iterdir` and a compiled pattern, never `Path.glob`: glob interprets its
        argument as a PATTERN, so an `[audit].path` containing `[`, `*` or `?`
        would search a different set of names than the pattern accepts -- and
        that mismatch EMPTIES the orphan guard below rather than tripping it.
        `iterdir` lists the directory once, which glob does anyway.
        """
        pattern = re.compile(
            re.escape(self.path.stem) + r"-\d{6,}" + re.escape(self.path.suffix)
        )
        return sorted(
            entry for entry in self.path.parent.iterdir() if pattern.fullmatch(entry.name)
        )

    def segments(self) -> list[Path]:
        """Every file this log is made of, OLDEST FIRST, active segment last.

        Walked BACKWARD from the active segment through the anchors, not globbed
        and sorted. The walk is content, so no filename can lie about where a
        segment belongs, no naming pattern has to be authoritative, and a missing
        segment is diagnosable AS a missing segment rather than as a hash
        mismatch at an arbitrary seq. Measured at 27us per segment -- 3% on a
        26-segment log -- so there is nothing here worth caching.

        PUBLIC, like `durability`: a test that asserts which files a log is made
        of should read the answer rather than mock its way to one.
        """
        if not self.path.exists():
            # `records()` answers "zero records" for a log that is not there and
            # warden/cli/replay.py depends on that -- it checks for the missing
            # file itself, first, and exits 2. This answers the matching question
            # the same way rather than raising where its caller does not.
            return []
        chain = [self.path]
        seen = {_identity(self.path)}
        cursor = self.path
        while (anchor := _anchor_of(cursor)) is not None:
            target = anchor.get("target")
            previous = target.get("previous") if isinstance(target, dict) else None
            if not isinstance(previous, str) or not previous or previous != Path(previous).name:
                # A log is precisely the artifact that may have been hand-edited,
                # so a crafted anchor must not become a file this code opens.
                # `previous != Path(previous).name` rejects every separator, ".."
                # and "." in one comparison -- Path("..").name is "".
                raise OSError(
                    f"audit segment {cursor.name} anchors to an illegal name: {previous!r}"
                )
            older = self.path.parent / previous
            if not older.exists():
                # Refused, not skipped. Verifying whatever suffix is present
                # reports `chain BROKEN at seq N`, which calls a deliberate
                # operator action tampering; returning the partial log silently is
                # worse, because `warden replay` would then print `chain intact`
                # over a log missing its beginning. Pruning an audit log is a real
                # need and B3 does not serve it.
                raise OSError(f"audit segment {previous} is missing, named by {cursor.name}")
            if _identity(older) in seen:
                # A hand-edited pair of anchors naming each other is an infinite
                # walk, and an audit tool that hangs is one that gets skipped.
                raise OSError(f"audit segment anchors form a cycle at {previous}")
            seen.add(_identity(older))
            chain.append(older)
            cursor = older
        strangers = [
            entry.name for entry in self._closed_segment_files() if _identity(entry) not in seen
        ]
        if strangers:
            # Every closed-segment-shaped file here must be reachable from the
            # active segment. This is what catches a log that FORKED: the fork's
            # segments are on disk and nothing names them, and without this the
            # log reads as a short, perfectly intact chain.
            raise OSError(f"audit log has segment files nothing in the chain names: {strangers}")
        return list(reversed(chain))

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for segment in self.segments()
            for line in segment.read_text().splitlines()
            if line.strip()
        ]

    def _fsync_directory(self) -> None:
        """fsync on a FILE makes its contents durable and says nothing about the
        DIRECTORY ENTRY that makes it findable.

        B2 established that for the log's first record; rotation needs it twice
        (see `_rotate`). One implementation of the pair, called from both.
        """
        if self.durability != "fsync":
            return
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _rotate(self, handle: BinaryIO) -> None:
        """Close the segment `handle` holds, and make a new one the active one.

        Called under the flock on `handle`, which is what makes the head read
        below still the head when the anchor is built from it.

        The ORDER is the whole design. `[audit].path` must never, at any instant,
        refer to an empty file once the log has a history: the naive rotation --
        rename the active file away and let the next append's "a+b" recreate it --
        leaves `_head_from_tail` reading an empty file, which answers
        (0, GENESIS_HASH), so the log restarts at seq 1 with every record still
        verifying and verify_chain() returning (True, None). Two chains in one
        log, both internally perfect, and nothing saying so. Spiked, before any of
        this was written.

        So the anchor goes into a staging file FIRST, and `[audit].path` moves
        straight from the old inode to a new one that already contains it. The
        link before the replace is what keeps the closing segment reachable, since
        the replace takes its name away.
        """
        seq, prev_hash = _head_from_tail(handle)
        closed = self.path.parent / self._closed_segment_name(seq)
        body = {
            "seq": seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            # Thirteen fields, the same thirteen every decision carries, on B7's
            # decision 9: a mint reused them precisely so the record shape stays
            # ONE shape and AuditLog needs no new field.
            #
            # The previous segment's head hash is `prev_hash` -- the field every
            # record already uses for exactly that. ROADMAP B3 asked for "an
            # anchor record carrying the previous segment's head hash" and
            # anticipated a fourteenth field; the anchor is simply the chain's
            # next record, so none is needed. What it adds is the previous
            # segment's NAME, and that is what lets an operator archive the
            # oldest segment and leave something verifiable behind.
            "task_id": "-",
            "agent_id": "warden",
            "purpose": "audit-segment-rotation",
            "action": {"type": ANCHOR_ACTION_TYPE},
            "target": {"kind": "segment", "previous": closed.name},
            # Bare "none", no `sha256:` prefix, on B7's reasoning about that exact
            # choice: args_digest wears its prefix when arguments conceptually
            # existed and were deliberately not read. Here there are none at all.
            "args_digest": "none",
            # Not "allow": nothing was authorised. Not a new word either --
            # "none" is what this chain already says for a thing that did not
            # exist (policy_bundle_digest, on a mint).
            "decision": "none",
            "rule": "audit.rotation",
            # The SHAPE is forced rather than meaningful: warden/cli/replay.py
            # subscripts task_state["data_classes_held"] for every record before
            # printing anything, so {} tracebacks the one tool that renders the
            # log -- and does so AFTER verify-chain reported it intact.
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
            # Same inode: a previous rotation was interrupted between this link
            # and the replace below, and this completes it rather than refusing.
            # Reads during that window are already correct, because the duplicate
            # name is skipped by inode identity.
        # ORDERING, not durability, and the one that is easy to leave out. The
        # replace below depends on both names created above, and both are
        # unfsynced directory metadata that POSIX orders in no way at all: a
        # filesystem free to make the replace durable while the link is not would
        # leave the closing segment with NO NAME and its records unrecoverable.
        # Journalling filesystems happen not to do that; 1.4ms once per ~123,000
        # records buys not depending on it.
        self._fsync_directory()
        os.replace(staging, self.path)
        # Durability, and B2's property one level up. The record this append is
        # about goes into the new segment after this returns and its bytes get the
        # existing per-append fsync -- but its NAME is this replace, so a replace
        # that is not durable leaves the record whose append() already returned in
        # a nameless inode.
        self._fsync_directory()

    def append(
        self,
        *,
        task_id: str,
        agent_id: str,
        purpose: str,
        action: dict,
        target: dict,
        args_digest: str,
        decision: str,
        rule: str,
        task_state: dict,
        policy_bundle_digest: str,
    ) -> dict:
        # At most ONE rotation per call, tracked here rather than re-derived from
        # the file. Without it a segment_bytes below one record makes every append
        # rotate, reopen, find the new segment also over the threshold and rotate
        # again until the deadline -- so appends FAIL rather than merely producing
        # tiny segments.
        rotated = False
        with self._lock:
            # ONE deadline for the whole call, not one per attempt. Giving each
            # attempt a fresh lock_timeout would let a retrying append hold a pool
            # thread for a multiple of the constant whose own comment is about one
            # wedged writer not wedging every worker.
            deadline = time.monotonic() + self._lock_timeout
            while True:
                # "a+b": append-only writes, but READABLE, which is what lets the
                # head be taken from the tail of the same descriptor the lock is
                # held on. Path.open rather than the builtin so the disk-full test
                # keeps its patch point.
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
                        # Read AFTER the lock, never before. This is the whole of B6:
                        # two processes that read the head outside the lock both chain
                        # onto the same record, and verify_chain reports that as
                        # tampering. Measured before this change -- four processes,
                        # 200 appends each: 800 records, 451 distinct seqs, BROKEN at
                        # seq 52.
                        seq, prev_hash = _head_from_tail(handle)
                        if (seq, prev_hash) == (0, GENESIS_HASH):
                            # This log holds no records -- and if closed segments sit
                            # beside it, appending here would start a SECOND chain at
                            # genesis: the exact fork the rotation order in _rotate
                            # exists to prevent, arriving by another route (an
                            # operator deleting the active file).
                            #
                            # Gated on the HEAD rather than on st_size == 0, because
                            # _head_from_tail answers genesis for a file of nothing
                            # but newlines too -- so a size test would leave a hole in
                            # exactly the place the code it guards already documents a
                            # special case for.
                            #
                            # Runs once in a log's life, so the directory scan costs
                            # nothing in steady state.
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
                        body = {
                            "seq": seq + 1,
                            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                            "task_id": task_id,
                            "agent_id": agent_id,
                            "purpose": purpose,
                            "action": action,
                            "target": target,
                            "args_digest": args_digest,
                            "decision": decision,
                            "rule": rule,
                            "task_state": task_state,
                            "policy_bundle_digest": policy_bundle_digest,
                            "prev_hash": prev_hash,
                        }
                        record = dict(body)
                        record["hash"] = record_hash(body)
                        # sort_keys, matching canonical_json. Without it the file's
                        # byte layout tracks dict insertion order, so a target built
                        # in a different order changes the file while every hash
                        # still verifies -- a diff that reads as tampering and
                        # checks as clean.
                        #
                        # Written and FLUSHED inside the lock. Releasing before the
                        # bytes are out would let the next writer read a tail that is
                        # still in a userspace buffer.
                        #
                        # The fsync below is NOT what makes that true, and it is worth
                        # saying so because this is the kind of thing that gets
                        # misremembered as load-bearing: B6's inter-process correctness
                        # is the PAGE CACHE serving the next process's tail read, which
                        # flush() is what provides. fsync is about power loss. Deleting
                        # the fsync would not break B6; deleting the flush would.
                        handle.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
                        handle.flush()
                        if self.durability == "fsync":
                            # B2. flush() reaches the kernel; this reaches the device.
                            #
                            # INSIDE the lock, which the `with` gives for free -- the
                            # flock is released by the close at the end of the block.
                            # Releasing it early to shorten the ~1.7ms hold would let
                            # the next writer chain onto a record that is still only in
                            # the page cache, and a content-linked chain that loses N
                            # while keeping N+1 has a prev_hash nobody can supply.
                            os.fsync(handle.fileno())
                            if seq == 0:
                                # This append CREATED the file -- `seq` is the head's,
                                # so zero means the log had no records. fsync on the
                                # file makes its CONTENTS durable and says nothing
                                # about the DIRECTORY ENTRY that makes it findable, so
                                # without this a power loss can lose the whole log,
                                # including record 1, whose append() already returned
                                # and whose action therefore went ahead. ~1.4ms, once
                                # per log, on the one append that needs it.
                                self._fsync_directory()
                        return record
                # Reopen: the file this writer holds is not the active segment
                # any more, either because another writer rotated it or because
                # this call just did. OUTSIDE the `with`, so the flock on a segment
                # that is no longer active is released before the retry -- and
                # before the OSError, which is the same type, and lands in the same
                # handlers, as the flock timeout in _acquire.
                if time.monotonic() >= deadline:
                    raise OSError(f"audit log {self.path} {reason}: gave up")

    def verify_chain(self) -> tuple[bool, int | None]:
        prev_hash = GENESIS_HASH
        for record in self.records():
            # Hash the whole stored record (minus the hash field itself),
            # not a fixed allowlist of fields: an attacker who injects an
            # extra key into a stored line must be caught here, and a
            # hardcoded field list would silently exclude it from
            # verification.
            body = {key: value for key, value in record.items() if key != "hash"}
            if record["prev_hash"] != prev_hash:
                return False, record["seq"]
            if record["hash"] != record_hash(body):
                return False, record["seq"]
            prev_hash = record["hash"]
        return True, None
