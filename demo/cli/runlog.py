"""Write every run to disk, with enough context to be evidence.

    runs/2026-07-30T19-14-02Z-explain-matrix.log     what you saw on screen
    runs/2026-07-30T19-14-02Z-explain-matrix.json    what produced it
    runs/index.jsonl                                 one hash-chained line per run

A saved printout is not proof of much on its own: it does not say which policy
produced it, which model, which commit, or whether it is the same file that was
written. So each run also writes a manifest naming all four, and the index is
hash-chained exactly like `broker/audit.py` — each line seals the one before it,
so a run cannot be quietly removed from or reordered in the history without
every later line failing to verify.

Tamper-evident, not tamper-proof, and for the same reason as the audit log:
nothing here prevents an edit, it only makes one detectable. Anyone with write
access to `runs/` can rewrite the whole chain. That is worth saying out loud
rather than implying more than it delivers.

Everything lands in `runs/`, which is gitignored — these are local evidence of
local runs, and they contain the full narration, which includes whatever the
agent read.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from demo.scenario.paths import POLICY_BUNDLE

RUNS = Path("runs")
INDEX = RUNS / "index.jsonl"
GENESIS_HASH = "0" * 64

# Fixed order, so the hash is reproducible across processes.
_BODY_FIELDS = ("seq", "started", "finished", "kind", "label", "argv",
                "model", "policy_digest", "commit", "log_sha256", "results")


class Tee:
    """Writes to the terminal and the log at once.

    Capturing with redirect_stdout alone would leave the operator staring at a
    blank screen for the length of a live run.
    """

    def __init__(self, *streams) -> None:
        self._streams = streams

    def write(self, text: str) -> int:
        for stream in self._streams:
            stream.write(text)
        return len(text)

    def flush(self) -> None:
        for stream in self._streams:
            stream.flush()

    def isatty(self) -> bool:
        return False


def _commit() -> str:
    """Which revision produced this. Absent is fine; wrong would not be."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return result.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _digest() -> str:
    try:
        from warden.broker.policy_digest import policy_bundle_digest

        return policy_bundle_digest([POLICY_BUNDLE])
    except Exception as exc:  # noqa: BLE001 — provenance is best-effort, never fatal
        # A broken bundle path must be visible in the evidence, not
        # indistinguishable from "no bundle was ever configured" -- verify-runs
        # accepted "unknown" happily either way, which is exactly the silent
        # failure this exists to surface instead.
        return f"unavailable: {exc}"


def _body_hash(record: dict) -> str:
    body = {field: record.get(field) for field in _BODY_FIELDS}
    body["prev_hash"] = record["prev_hash"]
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _last() -> tuple[int, str]:
    if not INDEX.exists():
        return 0, GENESIS_HASH
    seq, prev = 0, GENESIS_HASH
    for line in INDEX.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        seq, prev = record["seq"], record["hash"]
    return seq, prev


def verify_index() -> tuple[bool, int | None]:
    """Recompute the chain. Returns (ok, first bad seq)."""
    if not INDEX.exists():
        return True, None
    prev = GENESIS_HASH
    for line in INDEX.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record["prev_hash"] != prev or _body_hash(record) != record["hash"]:
            return False, record["seq"]
        prev = record["hash"]
    return True, None


class RunLog:
    """Context manager: tees the run to a file, then writes its manifest."""

    def __init__(self, kind: str, label: str) -> None:
        self.kind = kind
        self.label = label
        self.results: dict = {}
        self.model = ""
        self._started = datetime.now(timezone.utc)
        stamp = self._started.strftime("%Y-%m-%dT%H-%M-%SZ")
        RUNS.mkdir(exist_ok=True)
        self.log_path = RUNS / f"{stamp}-{kind}-{label}.log"
        self.manifest_path = self.log_path.with_suffix(".json")
        self._handle = None
        self._stdout = None

    def __enter__(self) -> "RunLog":
        self._handle = self.log_path.open("w", encoding="utf-8")
        self._stdout = sys.stdout
        sys.stdout = Tee(self._stdout, self._handle)
        return self

    def __exit__(self, *exc) -> bool:
        sys.stdout = self._stdout
        self._handle.close()
        digest = hashlib.sha256(self.log_path.read_bytes()).hexdigest()
        seq, prev = _last()
        record = {
            "seq": seq + 1,
            "started": self._started.isoformat(),
            "finished": datetime.now(timezone.utc).isoformat(),
            "kind": self.kind,
            "label": self.label,
            # argv, not the environment: an API key lives in the environment and
            # must never reach a file that exists to be shown to someone.
            "argv": sys.argv[1:],
            "model": self.model,
            "policy_digest": _digest(),
            "commit": _commit(),
            "log_sha256": digest,
            "results": self.results,
            "prev_hash": prev,
        }
        record["hash"] = _body_hash(record)
        self.manifest_path.write_text(json.dumps(record, indent=2) + "\n")
        with INDEX.open("a", encoding="utf-8") as index:
            index.write(json.dumps(record, sort_keys=True) + "\n")
        print(f"\n  logged → {self.log_path}  (seq {record['seq']}, "
              f"sha256 {digest[:12]}…)")
        return False
