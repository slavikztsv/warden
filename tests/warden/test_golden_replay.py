"""The renderer and reader are pinned against a frozen log.

`warden replay` reads a RECORDED log -- it never builds a policy input and
never calls the PDP -- so it cannot detect a policy regression. It is not a
policy gate (tests/test_golden_decisions.py is). What it does pin, exactly,
is that the reader and renderer keep turning the same bytes into the same
text.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GOLDEN = REPO_ROOT / "tests" / "golden"


def test_replay_of_the_frozen_log_is_byte_identical():
    expected = (GOLDEN / "replay-4711.txt").read_bytes()
    result = subprocess.run(
        [sys.executable, "-m", "warden.cli.replay", "replay", "4711",
         "--audit", str(GOLDEN / "audit-4711.jsonl")],
        cwd=REPO_ROOT, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == expected


def test_the_frozen_log_still_verifies():
    """If the chain over the golden ever breaks, the golden was edited."""
    result = subprocess.run(
        [sys.executable, "-m", "warden.cli.replay", "verify-chain",
         "--audit", str(GOLDEN / "audit-4711.jsonl")],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "chain intact: 7 records" in result.stdout


def test_the_frozen_log_is_the_documented_run():
    """Seven records, three denials, and the three rules the README names."""
    import json

    records = [
        json.loads(line)
        for line in (GOLDEN / "audit-4711.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(records) == 7
    assert [(r["action"]["tool"], r["decision"]) for r in records] == [
        ("read_document", "allow"),
        ("read_document", "allow"),
        ("query_customers", "allow"),
        ("query_customers", "deny"),
        ("http_fetch", "deny"),
        ("http_fetch", "deny"),
        ("send_email", "allow"),
    ]
    assert [r["rule"] for r in records if r["decision"] == "deny"] == [
        "rows.bounded", "egress.allowlist", "egress.pii_sink",
    ]
    # The subjects key is what a pre-R7 broker omitted, which denied every db
    # read as input.malformed and un-tainted the whole run.
    assert all("subjects" in r["target"] for r in records)
