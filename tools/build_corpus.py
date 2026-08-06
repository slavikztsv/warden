"""Regenerates the seven demo decision inputs from the frozen audit log.

The audit record stores everything the policy input needs except the two
token fields, which are fixed for the demo, and which are stated here rather
than guessed. Deriving the corpus from the log rather than hand-writing it is
what makes it faithful: verified on OPA 1.19.0 that all seven reconstructed
inputs reproduce their audited rule exactly, including both precedence picks.

The adversarial cases in the same directory are hand-authored. This script
never writes them and never touches expected.json for them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "golden"
CORPUS = GOLDEN / "decisions"

# From the token `warden-demo up` mints (demo/cli/main.py's `_mint_token`).
# Not in the audit record, because a record states what was decided, not
# what the token permitted.
TOKEN_FIELDS = {
    "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "counterparties": ["customer:8812"],
}

DEMO_CASES = [
    "demo-1-read-ticket",
    "demo-2-read-poisoned-kb",
    "demo-3-read-one-customer",
    "demo-4-bulk-read",
    "demo-5-exfil-to-attacker",
    "demo-6-exfil-to-allowlisted-sink",
    "demo-7-reply-to-customer",
]


def policy_input(record: dict) -> dict:
    return {
        "principal": {
            "agent_id": record["agent_id"],
            "task_id": record["task_id"],
            "purpose": record["purpose"],
            **TOKEN_FIELDS,
        },
        "action": {
            "type": record["action"]["type"],
            "tool": record["action"]["tool"],
            "args_digest": record["args_digest"],
        },
        "target": record["target"],
        "task_state": record["task_state"],
    }


def main() -> int:
    records = [
        json.loads(line)
        for line in (GOLDEN / "audit-4711.jsonl").read_text().splitlines()
        if line.strip()
    ]
    if len(records) != len(DEMO_CASES):
        print(f"expected {len(DEMO_CASES)} records, found {len(records)}", file=sys.stderr)
        return 1
    CORPUS.mkdir(parents=True, exist_ok=True)
    for name, record in zip(DEMO_CASES, records, strict=False):
        (CORPUS / f"{name}.json").write_text(
            json.dumps(policy_input(record), indent=2, sort_keys=True) + "\n"
        )
        print(f"wrote {name}.json  (audited rule: {record['rule']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
