"""The selection menu.

Two properties matter more than the rendering. First, every option must
dispatch to argv the CLI actually understands -- a menu that offers a
command that does not parse is worse than no menu. Second, an option that
cannot run right now must still be *visible and selectable*: the menu
doubles as the map of what this demo can do, and hiding the Docker and
live-model paths from a reviewer who has neither defeats the point.
"""

from __future__ import annotations

import pytest

from demo.cli import menu
from demo.cli.main import build_parser

READY = {"OPENROUTER_API_KEY": "k"}


def render(*, env=None, docker=True):
    return menu.render(env=env if env is not None else {}, docker=docker)


# --- every option is a real command ---------------------------------------


def test_every_option_dispatches_to_a_known_subcommand():
    known = set(build_parser()._subparsers._group_actions[0].choices)
    for option in menu.OPTIONS:
        assert option.argv, f"{option.name} dispatches nothing"
        assert option.argv[0] in known, f"{option.name} -> unknown command {option.argv[0]}"


def test_option_keys_are_unique_and_contiguous():
    keys = [option.key for option in menu.OPTIONS]
    assert keys == [str(n) for n in range(1, len(keys) + 1)]


def test_every_option_states_what_it_proves():
    for option in menu.OPTIONS:
        assert option.summary.strip(), f"{option.name} has no summary"
        assert option.proves.strip(), f"{option.name} claims to prove nothing"


def test_the_flags_each_option_passes_are_accepted_by_its_command():
    """explain/sweep parse their own argv by hand; the rest go through
    argparse. Either way an option must not carry a flag its target rejects."""
    for option in menu.OPTIONS:
        command, *flags = option.argv
        if command in ("explain", "sweep", "record"):
            continue  # hand-parsed; covered by test_every_option_dispatches
        parser = build_parser()
        parser.parse_args([command, *flags])  # raises SystemExit if wrong


# --- rendering ------------------------------------------------------------


def test_every_option_appears_on_screen():
    screen = render()
    for option in menu.OPTIONS:
        assert f" {option.key} " in screen or f"{option.key}  " in screen
        assert option.name in screen


def test_options_are_grouped_under_headings():
    screen = render()
    for group in {option.group for option in menu.OPTIONS}:
        assert group in screen


def test_docker_options_are_marked_when_docker_is_missing():
    screen = render(docker=False)
    assert "docker" in screen.lower()
    docker_option = next(o for o in menu.OPTIONS if o.needs == "docker")
    assert docker_option.name in screen


def test_live_options_are_marked_when_no_credential_is_present():
    screen = render(env={}, docker=True)
    live_option = next(o for o in menu.OPTIONS if o.needs == "live")
    assert live_option.name in screen
    assert menu.UNAVAILABLE_MARK in screen


def test_a_detected_provider_is_named_on_screen():
    assert "openrouter" in render(env=READY).lower()


def test_nothing_is_marked_unavailable_when_everything_is_present():
    assert menu.UNAVAILABLE_MARK not in render(env=READY, docker=True)


# --- availability ---------------------------------------------------------


def test_availability_explains_why_rather_than_just_saying_no():
    blocked = menu.availability(env={}, docker=False)
    reasons = {reason for reason in blocked.values() if reason}
    assert reasons, "nothing was reported unavailable"
    assert all(len(reason) > 4 for reason in reasons)


def test_recorded_options_are_available_with_no_docker_and_no_key():
    blocked = menu.availability(env={}, docker=False)
    offline = [o for o in menu.OPTIONS if o.needs == ""]
    assert offline, "no option runs offline"
    for option in offline:
        assert not blocked[option.key]


def test_sweep_requires_openrouter_specifically():
    """sweep.py exits on a missing OPENROUTER_API_KEY -- a gemini key is not
    enough, so the menu must not report it as ready."""
    sweep = next(o for o in menu.OPTIONS if o.argv[0] == "sweep")
    blocked = menu.availability(env={"GEMINI_API_KEY": "k"}, docker=True)
    assert blocked[sweep.key]
    ready = menu.availability(env={"OPENROUTER_API_KEY": "k"}, docker=True)
    assert not ready[sweep.key]


# --- selection ------------------------------------------------------------


class Recorder:
    def __init__(self, result=0):
        self.calls = []
        self.result = result

    def __call__(self, argv):
        self.calls.append(list(argv))
        return self.result


def run(answers, *, env=None, docker=True, result=0):
    dispatch = Recorder(result)
    answers = iter(answers)

    def read(_prompt=""):
        try:
            return next(answers)
        except StopIteration:
            raise EOFError

    code = menu.main(
        [], read=read, dispatch=dispatch, env=env if env is not None else READY,
        docker=docker, out=_Sink(),
    )
    return code, dispatch.calls


class _Sink:
    def write(self, _text):
        return None

    def flush(self):
        return None


def test_choosing_a_number_dispatches_that_options_argv():
    first = menu.OPTIONS[0]
    code, calls = run([first.key])
    assert calls == [list(first.argv)]
    assert code == 0


def test_the_dispatched_exit_code_is_returned_unchanged():
    code, _ = run([menu.OPTIONS[0].key], result=3)
    assert code == 3


def test_quit_dispatches_nothing():
    code, calls = run(["q"])
    assert calls == []
    assert code == 0


def test_an_empty_line_quits():
    code, calls = run([""])
    assert calls == []
    assert code == 0


def test_an_invalid_choice_reprompts_rather_than_exiting():
    first = menu.OPTIONS[0]
    code, calls = run(["999", "not-a-number", first.key])
    assert calls == [list(first.argv)]
    assert code == 0


def test_end_of_input_exits_cleanly():
    """Piped or non-interactive: no stdin, so there is nothing to select."""
    code, calls = run([])
    assert calls == []
    assert code == 0


def test_an_unavailable_option_is_still_selectable():
    """Detect and label, never block -- the command itself reports the real
    failure, and a reviewer without Docker can still see what would happen."""
    docker_option = next(o for o in menu.OPTIONS if o.needs == "docker")
    code, calls = run([docker_option.key], env={}, docker=False)
    assert calls == [list(docker_option.argv)]


def test_selection_by_name_works_too():
    first = menu.OPTIONS[0]
    _, calls = run([first.name])
    assert calls == [list(first.argv)]


# --- wiring into the CLI --------------------------------------------------


def test_bare_warden_demo_opens_the_menu(monkeypatch):
    opened = []
    monkeypatch.setattr(menu, "main", lambda argv, **kw: opened.append(argv) or 0)
    from demo.cli.main import main as cli_main

    assert cli_main([]) == 0
    assert opened == [[]]


def test_the_menu_subcommand_opens_the_menu(monkeypatch):
    opened = []
    monkeypatch.setattr(menu, "main", lambda argv, **kw: opened.append(argv) or 0)
    from demo.cli.main import main as cli_main

    assert cli_main(["menu"]) == 0
    assert opened == [[]]


def test_menu_is_listed_in_the_top_level_help():
    assert "menu" in build_parser().format_help()


@pytest.mark.parametrize("command", ["up", "verify-runs"])
def test_existing_subcommands_still_parse(command):
    """The menu is additive; nothing documented may stop working."""
    build_parser().parse_args([command])
