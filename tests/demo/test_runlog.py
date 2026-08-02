"""The run log exists to be shown to someone, so its claims must hold."""

import json
from pathlib import Path

import pytest

from demo.cli import runlog


@pytest.fixture
def runs(tmp_path, monkeypatch):
    monkeypatch.setattr(runlog, "RUNS", tmp_path / "runs")
    monkeypatch.setattr(runlog, "INDEX", tmp_path / "runs" / "index.jsonl")
    monkeypatch.chdir(tmp_path)
    return tmp_path / "runs"


def test_a_run_writes_its_output_and_a_manifest(runs):
    with runlog.RunLog("explain", "compare-triage") as run:
        print("bytes that left: 121")
        run.results = {"protected": {"refused": 3}}
        run.model = "recorded — support-triage.json"

    logs = list(runs.glob("*.log"))
    assert len(logs) == 1
    assert "bytes that left: 121" in logs[0].read_text()

    manifest = json.loads(logs[0].with_suffix(".json").read_text())
    assert manifest["kind"] == "explain"
    assert manifest["results"]["protected"]["refused"] == 3
    assert manifest["model"] == "recorded — support-triage.json"
    # Provenance is the reason this is evidence rather than a printout.
    for field in ("started", "finished", "commit", "policy_digest", "log_sha256"):
        assert manifest[field], field


def test_the_manifest_hash_matches_the_log_it_names(runs):
    import hashlib

    with runlog.RunLog("explain", "protected") as run:
        print("the transcript")
        run.results = {}
    log = next(runs.glob("*.log"))
    manifest = json.loads(log.with_suffix(".json").read_text())
    assert manifest["log_sha256"] == hashlib.sha256(log.read_bytes()).hexdigest()


def test_the_index_chains_runs_together(runs):
    for i in range(3):
        with runlog.RunLog("explain", f"run{i}") as run:
            print(i)
            run.results = {}
    lines = [json.loads(x) for x in runlog.INDEX.read_text().splitlines() if x.strip()]
    assert [r["seq"] for r in lines] == [1, 2, 3]
    assert lines[0]["prev_hash"] == runlog.GENESIS_HASH
    assert lines[1]["prev_hash"] == lines[0]["hash"]
    assert lines[2]["prev_hash"] == lines[1]["hash"]
    assert runlog.verify_index() == (True, None)


def test_editing_a_recorded_run_breaks_the_chain(runs):
    """The whole point. Tamper-evident, not tamper-proof: this detects the
    edit, it does not prevent it."""
    for i in range(3):
        with runlog.RunLog("explain", f"run{i}") as run:
            print(i)
            run.results = {"leaked": 121}

    lines = [json.loads(x) for x in runlog.INDEX.read_text().splitlines() if x.strip()]
    lines[1]["results"]["leaked"] = 0          # make a bad run look clean
    runlog.INDEX.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in lines) + "\n"
    )
    ok, bad = runlog.verify_index()
    assert not ok and bad == 2


def test_removing_a_run_breaks_the_chain(runs):
    """Deleting the inconvenient run is the other obvious edit."""
    for i in range(3):
        with runlog.RunLog("explain", f"run{i}") as run:
            print(i)
            run.results = {}
    lines = runlog.INDEX.read_text().splitlines()
    runlog.INDEX.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, bad = runlog.verify_index()
    assert not ok and bad == 3


def test_an_empty_index_verifies_rather_than_erroring(runs):
    assert runlog.verify_index() == (True, None)


def test_the_manifest_never_records_the_environment(runs):
    """An API key lives in the environment. A file that exists to be shown to
    someone must not carry one."""
    with runlog.RunLog("explain", "protected") as run:
        run.results = {}
    manifest = json.loads(next(runs.glob("*.json")).read_text())
    assert "env" not in manifest
    assert set(manifest) == {
        "seq", "started", "finished", "kind", "label", "argv", "model",
        "policy_digest", "commit", "log_sha256", "results", "prev_hash", "hash",
    }


def test_output_still_reaches_the_terminal(runs, capsys):
    """Capturing without teeing would leave the operator watching a blank
    screen for the length of a live run."""
    with runlog.RunLog("explain", "protected") as run:
        print("visible")
        run.results = {}
    assert "visible" in capsys.readouterr().out


def test_a_run_records_the_commit_it_started_at(runs, monkeypatch):
    """A long run can span a commit, and one did: run 2026-08-02T12-27-53Z
    started at 56c1579 and its manifest names 490267c, a commit made while it
    was still running. Nothing about a wrong hash looks uncertain, and the
    index chain seals it just as happily as a right one."""
    monkeypatch.setattr(runlog, "_commit", lambda: "commit-at-start")
    with runlog.RunLog("explain", "matrix-live") as run:
        monkeypatch.setattr(runlog, "_commit", lambda: "commit-at-end")
        run.results = {}

    log = next(runs.glob("*.log"))
    manifest = json.loads(log.with_suffix(".json").read_text())
    assert manifest["commit"] == "commit-at-start"
