"""Append-only, hash-chained decision log.

Tamper-evident, not tamper-proof: modifying a record breaks the chain and
becomes detectable, but nothing here prevents the edit.
"""

from __future__ import annotations

import hashlib
import json
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

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text().splitlines()
            if line.strip()
        ]

    def _head(self) -> tuple[int, str]:
        existing = self.records()
        if not existing:
            return 0, GENESIS_HASH
        last = existing[-1]
        return last["seq"], last["hash"]

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
        record["hash"] = record_hash(body)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
        return record

    def verify_chain(self) -> tuple[bool, int | None]:
        prev_hash = GENESIS_HASH
        for record in self.records():
            body = {field: record[field] for field in _BODY_FIELDS}
            if record["prev_hash"] != prev_hash:
                return False, record["seq"]
            if record["hash"] != record_hash(body):
                return False, record["seq"]
            prev_hash = record["hash"]
        return True, None
