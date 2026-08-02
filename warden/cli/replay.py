"""Reconstructs the attack path from the audit log.

This is the artifact you print and hand across the table.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from warden.broker.audit import AuditLog


def _describe(record: dict) -> str:
    tool = record["action"].get("tool", "?")
    target = record["target"]
    kind = target.get("kind")
    if kind == "http":
        return f"{tool}({target.get('host', '')}{target.get('path', '')})"
    if kind == "db":
        return f"{tool}(rows≈{target.get('estimated_rows', 0)})"
    if kind == "doc":
        return f"{tool}({target.get('path', '')})"
    if kind == "mail":
        return f"{tool}({', '.join(target.get('recipients', []))})"
    return f"{tool}()"


def render_replay(
    records: list[dict], *, chain_ok: bool | None = None, bad_seq: int | None = None
) -> str:
    """Renders one task's decisions.

    The chain verdict is an ARGUMENT, not something this function invents.
    Integrity is a property of the whole log, and the records handed here are
    filtered to a single task -- a per-task subset does not chain, because
    prev_hash links across tasks. Verifying what is actually shown is
    therefore impossible from inside the renderer; the caller must verify the
    log and say what it found.

    It defaults to None ("not verified") rather than True precisely because
    this line used to be printed unconditionally. `chain intact: N records`
    was emitted whether or not anything had been checked, so the artifact
    asserted the one property it never verified: flipping a deny to an allow
    in the log and replaying it printed the tampered record under "chain
    intact". A caller that forgets to verify now says so out loud instead of
    making a claim on the strength of nothing.
    """
    if not records:
        return "no records for that task\n"

    first = records[0]
    lines = [
        f"task {first['task_id']}  purpose={first['purpose']}  agent={first['agent_id']}"
    ]
    # Each record's task_state is the snapshot taken BEFORE that call ran, so
    # the first record showing pii is the one AFTER the read that caused it.
    # Emitting the marker before that record's own line therefore places it
    # directly beneath its cause. Emitting it after would attribute the taint
    # to the next call — in the demo, to the denied bulk read, making it look
    # as though the blocked query is what tainted the task.
    tainted = False
    for record in records:
        held = record["task_state"]["data_classes_held"]
        if "pii" in held and not tainted:
            tainted = True
            lines.append("      ⛔ TAINT: task now holds data_class=pii")
        mark = "✓" if record["decision"] == "allow" else "✗"
        verdict = "allow" if record["decision"] == "allow" else "DENY "
        # On an allow the broker records the rule as the literal "allow", so
        # printing it would render "allow  allow". Show the rule only when it
        # carries information — i.e. when it names why something was refused.
        reason = "" if record["rule"] == "allow" else f"  {record['rule']}"
        lines.append(f"  {mark} {_describe(record):<38} {verdict}{reason}".rstrip())
    head = str(records[-1].get("hash", "?"))[:8]
    if chain_ok is False:
        where = f" at seq {bad_seq}" if bad_seq is not None else ""
        lines.append(f"  ⚠ CHAIN BROKEN{where}: the audit log has been MODIFIED.")
        lines.append(
            f"  {len(records)} records shown; nothing above can be trusted. "
            f"head sha256:{head}…"
        )
    elif chain_ok is True:
        lines.append(f"  chain intact: {len(records)} records, head sha256:{head}…")
    else:
        lines.append(
            f"  chain NOT VERIFIED: {len(records)} records, head sha256:{head}…"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden")
    parser.add_argument("command", choices=["replay", "verify-chain", "config"])
    parser.add_argument("task_id", nargs="?", default=None)
    parser.add_argument("--audit", default="data/audit.jsonl")
    # No defaults for --catalog/--data: a default path into this repo's own
    # bundled demo scenario is exactly the scenario knowledge
    # tests/test_seam.py exists to keep out of warden/ -- `config` run with
    # no flags must ask for them rather than silently checking a demo it has
    # never heard of.
    # Validated below (only "config" uses them; "replay" and "verify-chain"
    # never pass them at all, so this cannot be plain argparse required=True
    # on a parser shared by all three commands).
    parser.add_argument("--catalog", default=None, help="path to your tools.toml")
    parser.add_argument("--data", default=None, help="path to your policy data.json")
    parser.add_argument("--opa", default=None)
    args = parser.parse_args(argv)

    if args.command == "config":
        if not args.catalog or not args.data:
            print("error: config requires --catalog and --data", file=sys.stderr)
            return 2
        # Offline, this compares tools.toml against data.json: two files
        # authored independently on purpose, so R1b stays a real check on a
        # broker that mislabels a target rather than a value compared with
        # itself. The cost is drift, and drift fails closed but SILENTLY --
        # a blanket input.malformed on every call to the affected tool,
        # visible only in production. --opa additionally reads data.tools
        # from a running server: the only way to catch a bundle mounted
        # where OPA namespaces the document to something other than
        # data.tools, which no file comparison can see.
        from warden.broker.config.check import check_catalog, check_catalog_findings

        problems = check_catalog(
            Path(args.catalog), Path(args.data), env=os.environ, opa_url=args.opa
        )
        for problem in problems:
            print(f"✗ {problem}", file=sys.stderr)
        # Advisory, never a reason to exit 1 -- see check.py's own docstring.
        for finding in check_catalog_findings(Path(args.catalog), env=os.environ):
            print(f"ℹ {finding}", file=sys.stderr)
        if problems:
            return 1
        print("config consistent")
        return 0

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

    def verify() -> tuple[bool, int | None, str | None]:
        """(ok, bad_seq, malformed_detail). Never raises.

        verify_chain() assumes every record carries the full body (prev_hash,
        ts, args_digest, ...) that AuditLog.append() writes. A record missing
        one of those fields — hand-edited, truncated, or otherwise malformed —
        is exactly what a tampered log looks like, so it is reported as broken
        rather than crashing the CLI.
        """
        try:
            ok, bad_seq = log.verify_chain()
        except (KeyError, TypeError) as exc:
            return False, None, str(exc)
        return ok, bad_seq, None

    if args.command == "verify-chain":
        ok, bad_seq, malformed = verify()
        if malformed is not None:
            print(f"chain BROKEN: malformed record ({malformed})")
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

    # Verify before rendering, and render what the verification actually
    # found. The chain covers the whole log, not just this task's records:
    # prev_hash links across tasks, so a subset never chains on its own, and
    # a tamper anywhere in the file invalidates everything after it.
    chain_ok, bad_seq, _ = verify()
    print(render_replay(records, chain_ok=chain_ok, bad_seq=bad_seq), end="")
    # The banner is not the whole answer: a caller that chains
    # `warden replay <task-id> && ...` would sail past a tampered log if the
    # exit code said success, and the verdict would live only in stdout. This is
    # the same command that used to assert integrity it had never checked --
    # it must not now check it and then shrug. `verify-chain` already exits 1;
    # so does this. `warden-demo up` (the demo CLI's `_cmd_up`) propagates
    # this exact exit code as its own return value, unmodified, so a broken
    # chain still aborts the run loudly -- the same property the retired
    # shell script got for free from `set -euo pipefail`. A demo that
    # completes cheerfully over a tampered audit log is worse than one that
    # stops.
    return 0 if chain_ok else 1


if __name__ == "__main__":
    sys.exit(main())
