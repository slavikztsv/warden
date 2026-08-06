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
    records = [json.loads(line) for line in
               (SCENARIO.parents[1] / "tests" / "golden" / "audit-4711.jsonl")
               .read_text().splitlines() if line.strip()]
    assert {r["task_id"] for r in records} == {task["task_id"]}
    assert {r["agent_id"] for r in records} == {task["agent_id"]}
    assert {r["purpose"] for r in records} == {task["purpose"]}


def test_the_mock_transport_routes_to_the_declared_sinkhole_host(monkeypatch):
    """`[scenario].sinkhole_host` must actually be consulted -- not just
    declared alongside a hardcoded 'attacker.example' that ignores it.

    `_mock_transport()`'s catch-all sends ANY unrecognised host to the
    sinkhole already, so posting to some made-up hostname would land there
    whether or not the config is actually wired in -- that check would prove
    nothing. What discriminates: declare `sinkhole_host` as a hostname that
    already has its OWN real backend (`docstore.internal`) and confirm the
    SINKHOLE answers there instead. If the code still hardcoded
    "attacker.example", `docstore.internal` would keep reaching the real
    docstore app and this would fail.
    """
    import httpx

    from demo.cli import explain as explain_module
    from demo.mocks import sinkhole

    monkeypatch.setitem(explain_module.SCENARIO, "sinkhole_host", "docstore.internal")
    sinkhole.RECEIVED.clear()
    client = httpx.Client(transport=explain_module._mock_transport())

    response = client.post("http://docstore.internal/anything", content=b"probe")

    assert response.json() == {"ok": True}, "docstore.internal's real backend answered, not the sinkhole"
    assert sinkhole.RECEIVED == ["probe"]


def test_no_shell_script_inlines_the_token_fields():
    """demo/scripts/demo.sh used to inline agent_id, task_id, purpose,
    allowed_tools and counterparties in a curl body -- the last hardcoded
    scenario blob. Task 24 replaced it with `warden-demo up`, which reads
    [task] from task.toml instead; this guards against the same literals
    creeping back into any shell script under demo/."""
    demo = SCENARIO.parent
    for script in demo.rglob("*.sh"):
        text = script.read_text()
        for needle in ("triage-bot", "support-triage", "customer:8812"):
            assert needle not in text, f"{script.name}: {needle}"


def test_every_task_and_scenario_key_is_read_somewhere():
    """Config that nothing consumes is the exact drift risk this file exists
    to remove -- someone changes it and nothing happens. Every key under
    [task], [scenario] and [prompts] must appear as a subscript (`[...]` or
    `.get(...)`) on TASK/SCENARIO/PROMPTS somewhere in demo/*.py."""
    config = tomllib.loads((SCENARIO / "task.toml").read_text())
    demo_src = "\n".join(
        path.read_text() for path in SCENARIO.parent.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    unread = []
    for table in ("task", "scenario", "prompts"):
        for key in config[table]:
            if f'"{key}"' not in demo_src and f"'{key}'" not in demo_src:
                unread.append(f"[{table}].{key}")
    assert unread == []
