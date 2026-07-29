"""Reconstructs the attack path from the audit log.

This is the artifact you print and hand across the table.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from broker.audit import AuditLog


def _describe(record: dict) -> str:
    tool = record["action"].get("tool", "?")
    target = record["target"]
    if target.get("kind") == "http":
        return f"{tool}({target.get('host', '')}{target.get('path', '')})"
    if target.get("kind") == "db":
        return f"{tool}(rows≈{target.get('estimated_rows', 0)})"
    return f"{tool}()"


def render_replay(records: list[dict]) -> str:
    if not records:
        return "no records for that task\n"

    first = records[0]
    lines = [
        f"task {first['task_id']}  purpose={first['purpose']}  agent={first['agent_id']}"
    ]
    tainted = False
    for record in records:
        mark = "✓" if record["decision"] == "allow" else "✗"
        verdict = "allow" if record["decision"] == "allow" else "DENY "
        lines.append(f"  {mark} {_describe(record):<38} {verdict}  {record['rule']}")
        held = record["task_state"]["data_classes_held"]
        if "pii" in held and not tainted:
            tainted = True
            lines.append("      ⛔ TAINT: task now holds data_class=pii")
    lines.append(
        f"  chain intact: {len(records)} records, head sha256:{records[-1]['hash'][:8]}…"
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden")
    parser.add_argument("command", choices=["replay", "verify-chain"])
    parser.add_argument("task_id", nargs="?", default=None)
    parser.add_argument("--audit", default="data/audit.jsonl")
    args = parser.parse_args(argv)

    audit_path = Path(args.audit)
    if not audit_path.exists():
        # AuditLog.records() treats a missing file as "zero records", which
        # would otherwise make verify-chain report a trivially "intact"
        # chain for a log that was never there — the one failure mode a
        # CI check cannot have. Catch it here, before that ambiguity forms,
        # for both commands.
        print(f"error: audit log not found: {audit_path}", file=sys.stderr)
        return 2

    log = AuditLog(audit_path)

    if args.command == "verify-chain":
        try:
            ok, bad_seq = log.verify_chain()
        except (KeyError, TypeError) as exc:
            # verify_chain() assumes every record carries the full body
            # (prev_hash, ts, args_digest, ...) that AuditLog.append() writes.
            # A record missing one of those fields — hand-edited, truncated,
            # or otherwise malformed — is exactly what a tampered log looks
            # like, so it is reported as broken rather than crashing the CLI.
            print(f"chain BROKEN: malformed record ({exc})")
            return 1
        if ok:
            print(f"chain intact: {len(log.records())} records")
            return 0
        print(f"chain BROKEN at seq {bad_seq}")
        return 1

    if not args.task_id:
        print("error: replay requires a task_id", file=sys.stderr)
        return 2

    records = [r for r in log.records() if r["task_id"] == args.task_id]
    if not records:
        print(f"no records for task {args.task_id}")
        return 0
    print(render_replay(records), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
