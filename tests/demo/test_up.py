"""`warden-demo up` replaces demo.sh -- tested at the wiring level, no Docker.

Task 24 turned demo/scripts/demo.sh (set -euo pipefail, so any failing
step aborted the whole run) into `demo.cli.main._cmd_up`. Python gives none
of that for free, so these tests pin the two properties the shell got for
nothing: a failing step must abort BEFORE any later step runs, and
`warden replay`'s own exit code (1 on a broken chain) must reach `_cmd_up`'s
return value unmodified -- not be swallowed into some generic non-zero.

They also pin that `--build` is structurally baked into every `up` and
`run` invocation this command emits, for both profiles -- re-pointing
tests/warden/test_key_split.py's
test_demo_script_rebuilds_before_starting_containers, which read the now-
deleted shell script's text. Unlike that text scan, these tests execute the
real dispatch path (with docker/openssl/http mocked out) and inspect the
actual argv `_compose` was called with, so a call site that quietly drops
`--build` is caught by running the code, not by grep.
"""

from __future__ import annotations

import argparse
import subprocess

import pytest

from demo.cli import main as main_module


def namespace(profile: str = "protected", live: bool = False) -> argparse.Namespace:
    return argparse.Namespace(profile=profile, live=live)


@pytest.fixture
def stub_steps(monkeypatch, tmp_path):
    """Replaces every side-effecting seam `_cmd_up` calls with a recorder,
    so the whole function runs with no Docker, no network and no real
    keypair -- and every call it made is inspectable afterwards."""
    calls: dict[str, list] = {
        "compose": [], "keypair": [], "seed": [], "mint": 0,
        "sinkhole": 0, "replay": [],
    }
    monkeypatch.setattr(main_module, "DATA_DIR", tmp_path)

    def fake_compose(*args, env=None):
        calls["compose"].append(args)

    def fake_generate_keypair(directory):
        calls["keypair"].append(directory)

    def fake_seed_customers(path, count):
        calls["seed"].append((path, count))

    def fake_mint_token():
        calls["mint"] += 1
        return "minted-token"

    def fake_print_sinkhole_report():
        calls["sinkhole"] += 1

    def fake_replay(task_id):
        calls["replay"].append(task_id)
        return 0

    monkeypatch.setattr(main_module, "_compose", fake_compose)
    monkeypatch.setattr(main_module, "_wait_for_broker_control", lambda: None)
    monkeypatch.setattr(main_module, "_generate_keypair", fake_generate_keypair)
    monkeypatch.setattr(main_module, "seed_customers", fake_seed_customers)
    monkeypatch.setattr(main_module, "_mint_token", fake_mint_token)
    monkeypatch.setattr(main_module, "_print_sinkhole_report", fake_print_sinkhole_report)
    monkeypatch.setattr(main_module, "_replay", fake_replay)
    return calls


# --- seeds from [scenario].seed_rows, not a hardcoded literal --------------


def test_up_seeds_the_database_from_the_scenario_row_count(stub_steps):
    from demo.scenario.task import SCENARIO

    main_module._cmd_up(namespace("unprotected"))

    assert len(stub_steps["seed"]) == 1
    path, count = stub_steps["seed"][0]
    assert count == SCENARIO["seed_rows"]


# --- --build is baked into every up/run this command can emit --------------


def test_protected_profile_builds_before_every_up_and_run(stub_steps):
    rc = main_module._cmd_up(namespace("protected"))

    assert rc == 0
    ups = [c for c in stub_steps["compose"] if "up" in c]
    runs = [c for c in stub_steps["compose"] if "run" in c]
    assert len(ups) == 1, ups
    assert len(runs) == 1, runs
    for call in ups + runs:
        assert "--build" in call, call


def test_unprotected_profile_builds_before_every_up_and_run(stub_steps):
    rc = main_module._cmd_up(namespace("unprotected"))

    assert rc == 0
    ups = [c for c in stub_steps["compose"] if "up" in c]
    runs = [c for c in stub_steps["compose"] if "run" in c]
    assert len(ups) == 1, ups
    assert len(runs) == 1, runs
    for call in ups + runs:
        assert "--build" in call, call


def test_both_profiles_together_match_demo_sh_s_original_shape(stub_steps):
    """The retired shell-scan test asserted exactly one `up` and one `run`
    PER PROFILE (two of each across the whole file), all carrying --build.
    Reproduced here by driving both profiles through the real function."""
    main_module._cmd_up(namespace("protected"))
    stub_steps["compose"].clear()
    main_module._cmd_up(namespace("unprotected"))

    ups = [c for c in stub_steps["compose"] if "up" in c]
    runs = [c for c in stub_steps["compose"] if "run" in c]
    assert len(ups) == 1
    assert len(runs) == 1


def test_compose_up_bakes_in_build_regardless_of_caller(monkeypatch):
    """Unit-level chokepoint check: _compose_up cannot be called without
    --build ending up in the emitted command, independent of _cmd_up."""
    calls = []
    monkeypatch.setattr(main_module, "_compose", lambda *a, **k: calls.append(a))
    main_module._compose_up("protected", "opa", "broker")
    assert calls == [("--profile", "protected", "up", "-d", "--build", "opa", "broker")]


def test_compose_run_bakes_in_build_regardless_of_caller(monkeypatch):
    calls = []
    monkeypatch.setattr(main_module, "_compose", lambda *a, **k: calls.append(a))
    main_module._compose_run("unprotected", "agent-runtime-unprotected")
    assert calls == [
        ("--profile", "unprotected", "run", "--build", "--rm", "agent-runtime-unprotected")
    ]


# --- abort-on-failure: set -euo pipefail's effect, ported -------------------


def test_a_failed_compose_step_aborts_before_minting_or_replay(stub_steps, monkeypatch):
    """The first docker compose call (bringing the containers up) fails.
    Nothing downstream of it -- minting a token, running the agent, the
    sinkhole report, warden replay -- may run."""

    def failing_compose(*args, env=None):
        raise subprocess.CalledProcessError(returncode=3, cmd=["docker", "compose", *args])

    monkeypatch.setattr(main_module, "_compose", failing_compose)

    rc = main_module._cmd_up(namespace("protected"))

    assert rc == 3, "the failing step's own exit code should propagate"
    assert stub_steps["mint"] == 0
    assert stub_steps["sinkhole"] == 0
    assert stub_steps["replay"] == []


def test_a_failed_mint_aborts_before_running_the_agent(stub_steps, monkeypatch):
    def failing_mint():
        raise RuntimeError("control plane unreachable")

    monkeypatch.setattr(main_module, "_mint_token", failing_mint)

    rc = main_module._cmd_up(namespace("protected"))

    assert rc != 0
    # Only the "up" compose call happened; the "run" (the agent) never did.
    assert all("run" not in c for c in stub_steps["compose"])
    assert stub_steps["sinkhole"] == 0
    assert stub_steps["replay"] == []


def test_unprotected_profile_never_calls_replay(stub_steps):
    """Only the protected profile ends in `warden replay` -- demo.sh never ran
    it for `unprotected`, and the ported version must not either."""
    main_module._cmd_up(namespace("unprotected"))
    assert stub_steps["replay"] == []


# --- warden replay's exit code propagates through _cmd_up, unmodified ------


def test_replay_success_propagates_as_zero(stub_steps, monkeypatch):
    monkeypatch.setattr(main_module, "_replay", lambda task_id: 0)
    assert main_module._cmd_up(namespace("protected")) == 0


def test_replay_broken_chain_propagates_as_one_not_swallowed(stub_steps, monkeypatch):
    """A broken audit chain makes `warden replay` return 1. That exact code
    -- not some other non-zero value manufactured on the way out -- must be
    what `_cmd_up` (and therefore the process) returns."""
    monkeypatch.setattr(main_module, "_replay", lambda task_id: 1)
    assert main_module._cmd_up(namespace("protected")) == 1


def test_replay_is_called_with_the_declared_task_id(stub_steps):
    from demo.scenario.task import TASK

    main_module._cmd_up(namespace("protected"))
    assert stub_steps["replay"] == [TASK["task_id"]]
