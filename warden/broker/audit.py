"""Append-only, hash-chained decision log.

Tamper-evident, not tamper-proof: modifying a record breaks the chain and
becomes detectable, but nothing here prevents the edit.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

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
# to leave undocumented. This one is a fixed constant in a single place. It
# becomes a knob when B2 adds `[audit].durability`, so the config surface
# changes once instead of twice.
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


class AuditLog:
    def __init__(self, path: Path, *, lock_timeout: float = _LOCK_TIMEOUT_SECONDS) -> None:
        self.path = Path(path)
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

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text().splitlines()
            if line.strip()
        ]

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
        with self._lock:
            # "a+b": append-only writes, but READABLE, which is what lets the
            # head be taken from the tail of the same descriptor the lock is
            # held on. Path.open rather than the builtin so the disk-full test
            # keeps its patch point.
            with self.path.open("a+b") as handle:
                _acquire(handle, self._lock_timeout)
                # Read AFTER the lock, never before. This is the whole of B6:
                # two processes that read the head outside the lock both chain
                # onto the same record, and verify_chain reports that as
                # tampering. Measured before this change -- four processes,
                # 200 appends each: 800 records, 451 distinct seqs, BROKEN at
                # seq 52.
                seq, prev_hash = _head_from_tail(handle)
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
                handle.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
                handle.flush()
                return record

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
