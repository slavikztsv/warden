"""Append-only, hash-chained decision log.

Tamper-evident, not tamper-proof: modifying a record breaks the chain and
becomes detectable, but nothing here prevents the edit.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64

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


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Guards the read-then-append critical section in `append`. The log
        # is single-process, so a threading.Lock is sufficient: it prevents
        # two concurrent callers (e.g. FastAPI sync handlers running in
        # Starlette's threadpool) from reading the same head and writing
        # conflicting records, which `verify_chain` would otherwise report
        # as tampering.
        self._lock = threading.Lock()
        # The chain head, or None until the first append reads it.
        #
        # Populated LAZILY, on first append, and deliberately not here.
        # `warden verify-chain` exists to be pointed at a CORRUPT log and
        # report "chain BROKEN: malformed record" -- and warden/cli/replay.py
        # constructs this object BEFORE the guard that produces that verdict.
        # A constructor that parsed the file would raise first, so the one
        # tool whose whole job is inspecting broken chains would traceback
        # instead of reporting one.
        #
        # The cost is one read per process, which is what happened on every
        # append before. The win was never the first append; it was the
        # four-thousandth, where re-parsing the whole log cost 37ms inside
        # the lock every concurrent caller queues on.
        self._head_cache: tuple[int, str] | None = None

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text().splitlines()
            if line.strip()
        ]

    def _head(self) -> tuple[int, str]:
        """The (seq, hash) the next record links to.

        Read from the file once and cached thereafter. Only ever called from
        `append`, under the lock -- so the first-append read cannot race a
        concurrent second append, and the cache is never populated twice.
        """
        if self._head_cache is None:
            existing = self.records()
            last = existing[-1] if existing else None
            self._head_cache = (
                (last["seq"], last["hash"]) if last else (0, GENESIS_HASH)
            )
        return self._head_cache

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
            seq, prev_hash = self._head()
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
            digest = record_hash(body)
            record["hash"] = digest
            with self.path.open("a", encoding="utf-8") as handle:
                # sort_keys, matching canonical_json. Without it the file's
                # byte layout tracks dict insertion order, so a target built
                # in a different order changes the file while every hash
                # still verifies -- a diff that reads as tampering and
                # checks as clean.
                handle.write(json.dumps(record, sort_keys=True) + "\n")
                handle.flush()
            # AFTER the write returns, never before: if it raised, the cache
            # still describes what is actually on disk, so the next append
            # computes from the true head rather than from a record that was
            # never written. Advancing first would break the chain at the
            # NEXT successful append -- one call removed from its cause.
            # Built from the typed locals rather than read back out of
            # `record`, whose values are `object` to a type checker.
            self._head_cache = (seq + 1, digest)
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
