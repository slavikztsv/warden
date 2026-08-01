"""The `warden-demo` console script: the support-ticket scenario, five ways.

Moved (Task 20): cli/, agent/ and mocks/ now live under demo/, and
scripts/demo.sh was demo/scripts/demo.sh. Task 24 absorbed that script into
`up` below (keygen, `docker compose` orchestration, token mint from
`task.toml`, sinkhole report) and deleted it -- no shim, since a shim is
exactly what moving to a real command was meant to avoid.

`explain`, `sweep` and `record` are a thin argv passthrough to an existing
module's own `main(argv)` -- those modules parse their own flags (including
their own `--help`) by hand. They are intercepted in `main()` BEFORE argparse
ever sees their arguments (see PASSTHROUGH below); `argparse.REMAINDER`
looked like the obvious way to do this via a subparser instead, and does not
work: when the first token after the subcommand name is itself an option
(`--live`, `--pause`, `--unguarded`, all of which these commands take),
CPython's subparsers dispatch reports it as an "unrecognized argument" of
the TOP-LEVEL parser rather than collecting it into REMAINDER -- a
longstanding argparse limitation (the remainder positional only reliably
grabs a leading token that is *not* option-like), not a bug in this
dispatcher. Confirmed by hand: `warden-demo explain --unguarded` raised
exactly that error before this file bypassed argparse for these three.
"""

from __future__ import annotations

import argparse
import importlib
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

from demo.mocks.seed_db import seed_customers
from demo.scenario.task import SCENARIO, TASK

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "data"

# command -> the module (under demo/cli/) whose main(argv) implements it.
# Checked in main() before argparse parses anything, for the REMAINDER
# reason explained above.
PASSTHROUGH = {
    "explain": "demo.cli.explain",
    "sweep": "demo.cli.sweep",
    "record": "demo.cli.record",
}


# --- `up`: everything the retired demo.sh did, natively --------------------
#
# demo.sh ran under `set -euo pipefail`: any failing step -- a compose
# invocation, the mint, the sinkhole probe, `warden replay` itself -- aborted
# the whole run rather than continuing over it. Python gets none of that for
# free, so every subprocess/HTTP call below is checked explicitly, and a
# failure short-circuits `_cmd_up` with a non-zero return before any later
# step runs (see the try/except there). `warden replay`'s own return value is
# handed straight back as `_cmd_up`'s return value, unmodified -- its exit
# code (1 on a broken chain) is what makes a tampered audit chain stop the
# demo instead of scrolling past it, and it must not be swallowed into some
# generic non-zero on the way out.


def _compose(*args: str, env: dict[str, str] | None = None) -> None:
    """One `docker compose` invocation against both compose files, run from
    the repo root.

    docker compose resolves compose.yml and demo/compose.demo.yml against the
    CURRENT WORKING DIRECTORY, not any script's location, and both files stay
    where they are (compose.yml at the repo root, demo/compose.demo.yml under
    demo/). Task 22 split a single docker-compose.yml into compose.yml (opa,
    broker, broker-control -- built from warden/Dockerfile, no demo code) and
    demo/compose.demo.yml (docstore, mailer, sinkhole and the two
    agent-runtime services -- built from demo/Dockerfile, which contains both
    trees by necessity). Every invocation names both files; cwd is pinned to
    REPO_ROOT so `warden-demo up` behaves the same regardless of the caller's
    own working directory.
    """
    command = ["docker", "compose", "-f", "compose.yml", "-f", "demo/compose.demo.yml", *args]
    full_env = {**os.environ, **env} if env else None
    subprocess.run(command, check=True, cwd=REPO_ROOT, env=full_env)


def _compose_up(profile: str, *services: str) -> None:
    # --build, always. Without it Compose reuses whatever image already
    # exists, so a code change silently never reaches the containers. An
    # image predating the R7 `subjects` field once emitted a target dict
    # without that key; the policy denied it input.malformed (correctly), the
    # task therefore never became tainted, and the PII POST to the
    # allowlisted internal endpoint went through -- with the chain reporting
    # itself intact. `--build` lives here, not at each call site, so it is
    # structurally impossible for an `up` invocation to omit it.
    _compose("--profile", profile, "up", "-d", "--build", *services)


def _compose_run(profile: str, service: str, *, env: dict[str, str] | None = None) -> None:
    # Same reasoning as _compose_up: --build baked in, not left to the
    # caller. `run` is what starts agent-runtime -- the service most likely
    # to go stale, since it carries the scenario code Task 20 moved -- and a
    # `run` line missing `--build` silently reused a pre-move image and
    # crashed on an import the pre-move image never had.
    _compose("--profile", profile, "run", "--build", "--rm", service, env=env)


def _generate_keypair(directory: Path) -> None:
    """Generates the Ed25519 keypair, OUTSIDE every container, if absent.

    It is handed out split: broker-control gets the private half and is the
    only thing that can mint; broker gets the public half and can only
    verify. Generating it inside the broker (as an earlier version did) meant
    the enforcement point held a signing key, so compromising the one service
    the agent can reach would have handed over the ability to mint arbitrary
    tokens.
    """
    private_path = directory / "agent.key"
    public_path = directory / "agent.pub"
    if not private_path.exists():
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(private_path)],
            check=True,
        )
        private_path.chmod(0o600)
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
        check=True,
    )


def _mint_token() -> str:
    """POSTs [task] from task.toml to the control plane and returns the
    minted token.

    localhost:8081 is broker-control, published to the host. The agent
    runtime cannot reach it: broker-control is on backend-net only.
    """
    body = {
        "agent_id": TASK["agent_id"],
        "task_id": TASK["task_id"],
        "purpose": TASK["purpose"],
        "allowed_tools": TASK["allowed_tools"],
        "data_classes": TASK["data_classes"],
        "counterparties": TASK["counterparties"],
    }
    response = httpx.post("http://localhost:8081/v1/tokens", json=body, timeout=30.0)
    response.raise_for_status()
    return response.json()["token"]


def _print_sinkhole_report() -> None:
    print(f"--- what reached {SCENARIO['sinkhole_host']} ---")
    response = httpx.get("http://localhost:8099/__received", timeout=30.0)
    sys.stdout.write(response.text[:600])
    print()


def _wait_for_broker_control() -> None:
    """`up -d` returns once the containers have STARTED, not once
    broker-control's Uvicorn app has finished booting -- give it a moment
    before minting, the same margin demo.sh's `sleep 3` gave it."""
    time.sleep(3)


def _replay(task_id: str) -> int:
    from warden.cli.replay import main as replay_main

    return replay_main(["replay", task_id, "--audit", str(DATA_DIR / "audit.jsonl")])


def _live_env_has_credential() -> bool:
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"):
        return True
    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        return False
    for line in env_file.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() in ("GEMINI_API_KEY", "ANTHROPIC_API_KEY") and value.strip():
            return True
    return False


def _cmd_up(args: argparse.Namespace) -> int:
    # `--live` drives the loop with a real model instead of the recorded
    # transcript. The cassette stays the default: it is deterministic, needs
    # no credential, and cannot fail in front of an audience.
    agent_args = "--live" if args.live else ""
    if args.live:
        if not _live_env_has_credential():
            print("--live needs GEMINI_API_KEY or ANTHROPIC_API_KEY in .env", file=sys.stderr)
            return 2
        print("--- live model: the agent reaches its provider only because that host")
        print("--- is on this purpose's egress_allow. Every call is still brokered.")

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        seed_customers(DATA_DIR / "customers.db", SCENARIO["seed_rows"])

        if args.profile == "unprotected":
            _compose_up("unprotected", "docstore", "mailer", "sinkhole")
            _compose_run(
                "unprotected", "agent-runtime-unprotected", env={"AGENT_ARGS": agent_args}
            )
            _print_sinkhole_report()
            return 0

        (DATA_DIR / "audit.jsonl").unlink(missing_ok=True)
        _generate_keypair(DATA_DIR)
        _compose_up(
            "guarded", "opa", "docstore", "mailer", "sinkhole", "broker", "broker-control"
        )
        _wait_for_broker_control()
        # localhost:8081 is broker-control, published to the host. The agent
        # runtime cannot reach it: broker-control is on backend-net only.
        token = _mint_token()
        _compose_run(
            "guarded", "agent-runtime",
            env={"AGENT_ARGS": agent_args, "TASK_TOKEN": token},
        )
        _print_sinkhole_report()
    except subprocess.CalledProcessError as exc:
        return exc.returncode or 1
    except Exception as exc:  # httpx errors, a missing openssl, etc.
        print(f"warden-demo up: {exc}", file=sys.stderr)
        return 1

    # Not caught above: this return value must reach the process exit code
    # exactly as `warden.cli.replay.main` computed it.
    return _replay(TASK["task_id"])


def _cmd_verify_runs(args: argparse.Namespace) -> int:
    # The run index, not the audit log: proof that the saved evidence of
    # each run (runs/*.log, runs/*.json) is the set that was written, in the
    # order it was written. Identical to warden/cli/replay.py's own
    # "verify-runs" branch -- duplicated rather than imported from there
    # because that module's replay/verify-chain are the two functions pinned
    # unchanged by the golden test, and this command is not one of them.
    from demo.cli.runlog import INDEX, verify_index

    if not INDEX.exists():
        print(f"no runs recorded yet ({INDEX})")
        return 0
    ok, bad = verify_index()
    count = sum(1 for line in INDEX.read_text().splitlines() if line.strip())
    if ok:
        print(f"run index intact: {count} runs")
        return 0
    print(f"run index BROKEN at seq {bad}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warden-demo")
    sub = parser.add_subparsers(dest="command", required=True)

    p_up = sub.add_parser("up", help="run the end-to-end demo (docker compose)")
    p_up.add_argument(
        "--profile", default="guarded", choices=["guarded", "unprotected"],
        help="which compose profile to run",
    )
    p_up.add_argument("--live", action="store_true", help="drive it with a real model")
    p_up.set_defaults(func=_cmd_up)

    # Registered here only so `warden-demo --help` lists them; main() diverts
    # their actual argv to the target module before argparse ever parses it
    # (see PASSTHROUGH and the module docstring), so these three carry no
    # arguments of their own.
    sub.add_parser("explain", help="narrated single run: guarded vs unguarded")
    sub.add_parser("sweep", help="measure injection susceptibility across models")
    sub.add_parser("record", help="record a live run into a replayable cassette")

    p_verify = sub.add_parser(
        "verify-runs", help="verify runs/index.jsonl's hash chain"
    )
    p_verify.set_defaults(func=_cmd_verify_runs)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)

    if argv and argv[0] in PASSTHROUGH:
        module = importlib.import_module(PASSTHROUGH[argv[0]])
        return module.main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
