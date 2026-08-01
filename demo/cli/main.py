"""The `warden-demo` console script: the support-ticket scenario, five ways.

NOT YET MOVED. cli/, agent/ and mocks/ still live at the repo root, and
scripts/demo.sh hasn't moved under demo/scripts/ yet (Task 20). This module
therefore imports the top-level `cli.*` package and shells out to the
still-at-the-root demo.sh, the same way `python -m cli.explain` and
`./scripts/demo.sh` already do. Task 20 rewrites the imports to
`demo.cli.*`; Task 24 replaces the `up` subcommand's subprocess call to
demo.sh with a native implementation (demo.sh is retired then, not before).

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
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# command -> the module (still at the pre-Task-20 top-level `cli` package)
# whose main(argv) implements it. Checked in main() before argparse parses
# anything, for the REMAINDER reason explained above.
PASSTHROUGH = {
    "explain": "cli.explain",
    "sweep": "cli.sweep",
    "record": "cli.record",
}


def _cmd_up(args: argparse.Namespace) -> int:
    # scripts/demo.sh: "PROFILE=${1:-guarded} MODE=${2:-cassette}"; a second
    # positional of "--live" swaps the recorded transcript for a real model.
    demo_sh = REPO_ROOT / "scripts" / "demo.sh"
    command = [str(demo_sh), args.profile]
    if args.live:
        command.append("--live")
    return subprocess.call(command)


def _cmd_verify_runs(args: argparse.Namespace) -> int:
    # The run index, not the audit log: proof that the saved evidence of
    # each run (runs/*.log, runs/*.json) is the set that was written, in the
    # order it was written. Identical to cli/warden.py's own "verify-runs"
    # branch -- duplicated rather than imported from there because that
    # module's replay/verify-chain are the two functions pinned unchanged by
    # the golden test, and this command is not one of them.
    from cli.runlog import INDEX, verify_index

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
        "profile", nargs="?", default="guarded", choices=["guarded", "unprotected"]
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
