"""The `warden` console script: five subcommands over the product.

NOT YET MOVED. broker/, cli/ and policies/ still live at the repo root
(Task 20 relocates them to warden/broker, warden/cli/replay.py and
warden/policies). This module therefore imports the top-level `broker.*`
and `cli.*` packages -- the same ones `python -m broker`, `python -m
broker.control_main` and `python -m cli.warden` already import -- rather
than anything under `warden.*`. That only works because this package is
installed editable from a checkout that still has those directories as
siblings on sys.path; Task 20 rewrites every import here to `warden.broker.*`
/ `warden.cli.replay`, at which point the product wheel will actually be
self-contained.

`replay` and `verify-chain` delegate to cli.warden.main() UNCHANGED -- that
function (not a reimplementation of it) is what test_golden_replay.py pins
byte-for-byte. `serve` and `control` load TOML and call the Phase 1
entrypoints (broker/__main__.py, broker/control_main.py). `config check`
calls broker.config.check.check_catalog directly, the same function
cli/warden.py's own (still-live, still-used-by-CI) `config` command calls.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# The dotted module that implements `serve`. Task 21's seam test walks the
# import graph starting HERE to assert the serving process reaches no
# Signer -- `control` legitimately does import Signer, and serve/control
# share this one binary, so the walk needs a named starting point rather
# than warden.cli.main itself (which imports both, lazily, below).
SERVE_ENTRYPOINT = "broker.__main__"


def _cmd_serve(args: argparse.Namespace) -> int:
    if args.config:
        os.environ["WARDEN_CONFIG"] = args.config
    import broker.__main__ as serve_mod

    asyncio.run(serve_mod.main())
    return 0


def _cmd_control(args: argparse.Namespace) -> int:
    if args.config:
        os.environ["WARDEN_CONTROL_CONFIG"] = args.config
    import broker.control_main as control_mod

    control_mod.main()
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    from cli.warden import main as cli_warden_main

    argv = ["replay"]
    if args.task_id is not None:
        argv.append(args.task_id)
    argv += ["--audit", args.audit]
    return cli_warden_main(argv)


def _cmd_verify_chain(args: argparse.Namespace) -> int:
    from cli.warden import main as cli_warden_main

    return cli_warden_main(["verify-chain", "--audit", args.audit])


def _cmd_config_check(args: argparse.Namespace) -> int:
    from broker.config.check import check_catalog

    problems = check_catalog(
        Path(args.catalog), Path(args.data), env=os.environ, opa_url=args.opa
    )
    for problem in problems:
        print(f"✗ {problem}", file=sys.stderr)
    if problems:
        return 1
    print("config consistent")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warden")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser(
        "serve", help="run the agent-facing broker: tool API + egress proxy"
    )
    p_serve.add_argument(
        "--config",
        default=None,
        help="path to warden.toml (default: $WARDEN_CONFIG or /config/warden.toml)",
    )
    p_serve.set_defaults(func=_cmd_serve)

    p_control = sub.add_parser(
        "control", help="run the control plane: the only process that mints tokens"
    )
    p_control.add_argument(
        "--config",
        default=None,
        help="path to control.toml (default: $WARDEN_CONTROL_CONFIG or /config/control.toml)",
    )
    p_control.set_defaults(func=_cmd_control)

    p_replay = sub.add_parser(
        "replay", help="reconstruct one task's decisions from the audit log"
    )
    p_replay.add_argument("task_id", nargs="?", default=None)
    p_replay.add_argument("--audit", default="data/audit.jsonl")
    p_replay.set_defaults(func=_cmd_replay)

    p_verify = sub.add_parser("verify-chain", help="verify the audit log's hash chain")
    p_verify.add_argument("--audit", default="data/audit.jsonl")
    p_verify.set_defaults(func=_cmd_verify_chain)

    p_config = sub.add_parser("config", help="catalog / policy consistency checks")
    config_sub = p_config.add_subparsers(dest="config_command", required=True)
    p_check = config_sub.add_parser(
        "check", help="cross-check the tool catalog against policies/data.json"
    )
    p_check.add_argument("--catalog", default="demo/scenario/tools.toml")
    p_check.add_argument("--data", default="policies/data.json")
    p_check.add_argument("--opa", default=None)
    p_check.set_defaults(func=_cmd_config_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
