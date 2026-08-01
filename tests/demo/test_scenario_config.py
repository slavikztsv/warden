"""The scenario is config, not string literals in five modules."""

from __future__ import annotations

import tomllib
from pathlib import Path

SCENARIO = Path(__file__).resolve().parents[2] / "demo" / "scenario"


def test_the_task_is_declared_once():
    task = tomllib.loads((SCENARIO / "task.toml").read_text())["task"]
    assert task["task_id"] == "4711"
    assert task["purpose"] == "support-triage"
    assert task["counterparties"] == ["customer:8812"]
    assert set(task["allowed_tools"]) == {
        "read_document", "query_customers", "http_fetch", "send_email"
    }


def test_the_documents_are_files():
    documents = SCENARIO / "documents"
    assert (documents / "ticket-4711.txt").is_file()
    assert (documents / "kb" / "refund-policy.backup.txt").is_file()
    for payload in ("recon", "qa", "audit"):
        assert (documents / "kb" / f"refund-policy.{payload}.txt").is_file()


def test_no_scenario_string_remains_in_demo_python():
    """The prompt, the ticket and the four poison payloads were literals in
    agent/loop.py and mocks/docstore.py; explain.py restated the prompt in six
    of its ten TASKS entries."""
    demo = SCENARIO.parent
    offenders = []
    for path in demo.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text()
        for needle in ("Triage support ticket #4711", "SYSTEM MAINTENANCE NOTICE",
                       "Refunds for duplicate charges"):
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == []


def test_the_declared_token_matches_the_golden_run():
    """If these drift, the frozen audit log stops being reproducible."""
    import json
    task = tomllib.loads((SCENARIO / "task.toml").read_text())["task"]
    records = [json.loads(l) for l in
               (SCENARIO.parents[1] / "tests" / "golden" / "audit-4711.jsonl")
               .read_text().splitlines() if l.strip()]
    assert {r["task_id"] for r in records} == {task["task_id"]}
    assert {r["agent_id"] for r in records} == {task["agent_id"]}
    assert {r["purpose"] for r in records} == {task["purpose"]}
