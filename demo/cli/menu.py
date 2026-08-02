"""A selection menu over everything this demo can run.

`warden-demo` has grown a lot of surface -- five subcommands, and `explain`
alone takes eight flags across four scenarios -- and `--help` lists the
switches without saying which run is worth watching or what each one is
supposed to demonstrate. This is that map: every run, grouped by what it is
for, each carrying what it proves and what it costs.

Two rules shape it.

  · It dispatches, it does not reimplement. Every entry hands an argv to
    demo/cli/main.py's own main(), so the menu can never drift into being a
    second, subtly different way to run the demo.
  · An option that cannot run right now is still shown and still selectable,
    marked with the reason. Hiding the Docker and live-model paths from a
    reviewer who has neither would hide most of what this project does.

Timings are measured on the recorded path (which needs no network), not
estimated. They are labels on a menu, not a benchmark.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from demo.cli import preflight

UNAVAILABLE_MARK = "⚠"

# ANSI, applied only to a real terminal. The rest of this demo renders the
# same way (see demo/cli/explain.py), and a piped or captured run stays
# plain text so runs/*.log holds what a reader can diff.
_DIM = "\033[2m"
_BOLD = "\033[1m"
_ACCENT = "\033[35m"
_WARN = "\033[33m"
_OFF = "\033[0m"


@dataclass(frozen=True)
class Choice:
    """One answer to a Prompt, and the flags choosing it contributes."""

    key: str
    name: str
    detail: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class Prompt:
    """A follow-up question. `choices` is a callable, not a tuple, for one
    reason: the task list belongs to demo/cli/explain.py, and importing that
    module costs FastAPI's test client -- not worth paying to draw a menu the
    operator may never drill into. Resolving it at prompt time also means the
    menu cannot offer a task the CLI does not have."""

    title: str
    choices: Callable[[], tuple[Choice, ...]]


def task_choices() -> tuple[Choice, ...]:
    from demo.cli.explain import TASKS

    return tuple(
        Choice(str(n), name, spec.get("trips", ""), ("--task", name))
        for n, (name, spec) in enumerate(TASKS.items(), start=1)
    )


def mode_choices() -> tuple[Choice, ...]:
    return (
        Choice("1", "protected", "every tool call goes through the broker", ()),
        Choice(
            "2", "unprotected",
            "no broker at all: the agent holds the credentials itself",
            ("--unprotected",),
        ),
        Choice(
            "3", "both",
            "run each and print them side by side — the broker is the only variable",
            ("--compare",),
        ),
    )


@dataclass(frozen=True)
class Option:
    key: str
    name: str
    group: str
    summary: str
    proves: str
    cost: str
    argv: tuple[str, ...]
    needs: str = ""  # "" | "docker" | "live" | "openrouter"
    # Asked in order when this option is chosen; each answer's args are
    # appended to argv. Empty for options that are already one command.
    prompts: tuple[Prompt, ...] = ()


GROUP_ORDER = (
    "THE PITCH",
    "ONE SCENARIO, STEP BY STEP",
    "FULL STACK — real containers, real OPA, real proxy (Docker)",
    "A REAL MODEL — nothing recorded",
    "EVIDENCE",
)

OPTIONS: tuple[Option, ...] = (
    Option(
        key="1", name="matrix", group="THE PITCH",
        summary="every scenario's A/B on one screen",
        proves="seven scenarios, seven rules, one recorded transcript",
        cost="~3s · offline",
        argv=("explain", "--matrix"),
    ),
    Option(
        key="2", name="compare", group="THE PITCH",
        summary="protected vs unprotected, side by side",
        proves="identical model output both sides — the broker is the only variable",
        cost="~1s · offline",
        argv=("explain", "--compare", "--quiet-why"),
    ),
    Option(
        key="3", name="narrate", group="ONE SCENARIO, STEP BY STEP",
        summary="eleven stages per step, paused between each",
        proves="the real policy input, the rule that fired, the audit write before execution",
        cost="interactive · offline",
        argv=("explain", "--pause"),
    ),
    Option(
        key="4", name="protected", group="ONE SCENARIO, STEP BY STEP",
        summary="one brokered run, narrated end to end",
        proves="every refusal names the rule that produced it",
        cost="~1s · offline",
        argv=("explain",),
    ),
    Option(
        key="5", name="unprotected", group="ONE SCENARIO, STEP BY STEP",
        summary="the same run with no broker at all",
        proves="what the planted instruction achieves unopposed",
        cost="~1s · offline",
        argv=("explain", "--unprotected"),
    ),
    Option(
        key="6", name="up",
        group="FULL STACK — real containers, real OPA, real proxy (Docker)",
        summary="the whole system on agent-net, with no gateway",
        proves="containment is topological, not a check in code",
        cost="minutes · builds images",
        argv=("up", "--profile", "protected"),
        needs="docker",
    ),
    Option(
        key="7", name="breach",
        group="FULL STACK — real containers, real OPA, real proxy (Docker)",
        summary="the same agent with the broker not running",
        proves="the control case — the customer data actually leaves",
        cost="minutes · builds images",
        argv=("up", "--profile", "unprotected"),
        needs="docker",
    ),
    Option(
        key="8", name="live", group="A REAL MODEL — nothing recorded",
        summary="pick a task and a mode, then run it against a real model",
        proves="whichever rule that task is built to trip, against an unscripted model",
        cost="costs tokens",
        argv=("explain", "--live"),
        needs="live",
        prompts=(
            Prompt("Which task?", task_choices),
            Prompt("Which mode?", mode_choices),
        ),
    ),
    Option(
        key="9", name="live-matrix", group="A REAL MODEL — nothing recorded",
        summary="every scenario at once, driven by a real model",
        proves="the controls do not depend on the model behaving",
        cost="costs tokens · slow on a rate-limited free tier",
        argv=("explain", "--matrix", "--live"),
        needs="live",
    ),
    Option(
        key="10", name="sweep", group="A REAL MODEL — nothing recorded",
        summary="how often each model follows the planted instruction",
        proves="model refusal is probabilistic — measured, never counted as a control",
        cost="costs tokens · many calls",
        argv=("sweep",),
        needs="openrouter",
    ),
    Option(
        key="11", name="runs", group="EVIDENCE",
        summary="verify the hash chain over every run recorded so far",
        proves="a run cannot be edited out of the history unnoticed",
        cost="instant · offline",
        argv=("verify-runs",),
    ),
)


def availability(*, env: Mapping[str, str], docker: bool) -> dict[str, str]:
    """option key -> "" when runnable, else why not. Never blocks anything;
    the reason is a label, and the command itself remains selectable."""
    provider = preflight.live_provider(env)
    reasons = {
        "docker": "" if docker else "needs Docker — no docker binary on PATH",
        "live": "" if provider else "needs a model API key — none in the environment or .env",
        "openrouter": (
            "" if preflight.has_openrouter(env)
            else "needs OPENROUTER_API_KEY specifically"
        ),
        "": "",
    }
    return {option.key: reasons[option.needs] for option in OPTIONS}


def _paint(text: str, colour: str, *, colour_on: bool) -> str:
    return f"{colour}{text}{_OFF}" if colour_on else text


def render(*, env: Mapping[str, str], docker: bool, colour: bool = False) -> str:
    blocked = availability(env=env, docker=docker)
    provider = preflight.live_provider(env)

    lines = [
        "",
        _paint("  warden — what would you like to run?", _BOLD, colour_on=colour),
        _paint(
            "  every option below runs the real broker, the real policy and the real audit chain",
            _DIM, colour_on=colour,
        ),
        "",
        "  " + _paint(
            f"docker {'found' if docker else 'not found'}   ·   "
            f"live model {provider if provider else 'no key found'}",
            _DIM, colour_on=colour,
        ),
    ]

    for group in GROUP_ORDER:
        members = [option for option in OPTIONS if option.group == group]
        if not members:
            continue
        lines += ["", "  " + _paint(group, _ACCENT, colour_on=colour)]
        for option in members:
            reason = blocked[option.key]
            mark = f" {UNAVAILABLE_MARK}" if reason else ""
            lines.append(
                f"  {option.key:>3}  {_paint(option.name, _BOLD, colour_on=colour):<12}"
                f"  {option.summary}{mark}"
            )
            lines.append(
                "       " + _paint(f"{option.proves}", _DIM, colour_on=colour)
            )
            detail = reason if reason else option.cost
            colour_for_detail = _WARN if reason else _DIM
            lines.append(
                "       " + _paint(detail, colour_for_detail, colour_on=colour)
            )

    footer = "pick a number or a name · Enter or q to quit"
    if any(blocked.values()):
        # Only explain the mark when one is actually on screen. A legend for a
        # symbol that does not appear reads as a warning about nothing.
        footer += (
            f" · anything marked {UNAVAILABLE_MARK} still runs,"
            " and will tell you what is missing"
        )
    lines += ["", "  " + _paint(footer, _DIM, colour_on=colour), ""]
    return "\n".join(lines)


def _lookup(answer: str) -> Option | None:
    answer = answer.strip().lower()
    for option in OPTIONS:
        if answer in (option.key, option.name):
            return option
    return None


def render_prompt(prompt: Prompt, *, colour: bool = False) -> str:
    lines = ["", "  " + _paint(prompt.title, _BOLD, colour_on=colour)]
    for choice in prompt.choices():
        lines.append(
            f"  {choice.key:>3}  {_paint(choice.name, _BOLD, colour_on=colour):<16}"
            f"  {_paint(choice.detail, _DIM, colour_on=colour)}"
        )
    lines.append("")
    return "\n".join(lines)


class _Abort(Exception):
    """The operator backed out of a follow-up question."""


def _ask(prompt: Prompt, *, read, out, colour: bool) -> Choice:
    """Asks one follow-up question. Raises _Abort on quit or end of input.

    Same rules as the main menu, so there is one thing to learn: a number or a
    name selects, an empty line or q backs out, anything else re-asks.
    """
    out.write(render_prompt(prompt, colour=colour) + "\n")
    out.flush()
    choices = prompt.choices()
    while True:
        try:
            answer = read("  Select: ")
        except (EOFError, KeyboardInterrupt):
            out.write("\n")
            raise _Abort from None
        cleaned = answer.strip().lower()
        if not cleaned or cleaned in ("q", "quit", "exit"):
            raise _Abort
        for choice in choices:
            if cleaned in (choice.key, choice.name):
                return choice
        out.write(f"  no such choice: {answer.strip()!r}\n")
        out.flush()


def main(
    argv: list[str] | None = None,
    *,
    read=input,
    dispatch=None,
    env: Mapping[str, str] | None = None,
    docker: bool | None = None,
    out=None,
) -> int:
    """Renders the menu and runs one selection.

    One selection, not a loop back to the menu: several options take over the
    terminal (`--pause`) or the machine (`up`), and returning their exit code
    unchanged is what lets `warden-demo` stay scriptable and lets a broken
    audit chain still fail the process.
    """
    del argv  # the menu takes no arguments of its own
    out = sys.stdout if out is None else out
    env = preflight.merged_env() if env is None else env
    docker = preflight.docker_available() if docker is None else docker
    if dispatch is None:
        def dispatch(selected_argv):
            from demo.cli.main import main as cli_main

            return cli_main(selected_argv)

    colour = bool(getattr(out, "isatty", lambda: False)())
    out.write(render(env=env, docker=docker, colour=colour) + "\n")
    out.flush()

    while True:
        try:
            answer = read("  Select: ")
        except (EOFError, KeyboardInterrupt):
            # Piped, redirected, or Ctrl-C: there is nothing to select, and
            # exiting 0 keeps `warden-demo | head` from looking like a failure.
            out.write("\n")
            return 0

        if not answer.strip() or answer.strip().lower() in ("q", "quit", "exit"):
            return 0

        option = _lookup(answer)
        if option is None:
            out.write(f"  no such option: {answer.strip()!r}\n")
            out.flush()
            continue

        selected = list(option.argv)
        try:
            for prompt in option.prompts:
                selected += list(_ask(prompt, read=read, out=out, colour=colour).args)
        except _Abort:
            # Backing out of a follow-up returns to the shell rather than to
            # the menu: the menu is a way in, not a mode to be trapped in.
            return 0

        out.write(f"\n  $ warden-demo {' '.join(selected)}\n\n")
        out.flush()
        return dispatch(selected)
