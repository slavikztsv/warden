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
# Not in these records, because a DECISION record states what was decided,
# not what the token permitted. B7 changed that for the log as a whole -- the
# control plane now writes a `mint` record whose `target` IS the grant -- but
# not for the seven here: this file reads the FROZEN golden chain, which was
# captured before B7 and is never regenerated.
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


def task_state(record: dict) -> dict:
    """The record's task_state, in the vocabulary the CURRENT policy speaks.

    The frozen log predates P2·A's rename of `rows_returned_so_far` to
    `rows_charged_so_far`, and it stays that way on purpose: it is a real
    hash-chained log captured from a real run, and rewriting it to look like
    today's broker wrote it is precisely the edit tests/golden/README.md
    forbids. So the translation lives here, in the derivation, rather than in
    the artifact.

    Renaming rather than adding: a corpus input carrying the old key would be
    denied `input.malformed` by every rule that reads the new one -- loudly,
    which is the property the rename was chosen for, and useless as a
    regression corpus.
    """
    state = dict(record["task_state"])
    if "rows_returned_so_far" in state:
        state["rows_charged_so_far"] = state.pop("rows_returned_so_far")
    return state


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
            # `.get`, because not every record type has a tool: `tool_list`,
            # `mcp_handshake` and B7's `mint` each carry a type alone.
            # Defensive and unreachable today -- the golden chain is seven
            # tool_calls and main()'s count gate below returns 1 before this
            # is ever called on anything else -- but an unguarded subscript
            # here would be a KeyError rather than a diagnosis if the golden
            # were ever recaptured from a run that has one.
            "tool": record["action"].get("tool", record["action"]["type"]),
            "args_digest": record["args_digest"],
        },
        "target": record["target"],
        "task_state": task_state(record),
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
