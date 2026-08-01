"""Every recorded cassette must still be an answer to the prompt it replays as.

`Cassette.next_step` ignores the prompt text entirely -- it replays canned
steps in order no matter what `messages[0]["content"]` says. So if a TASKS
entry's `"say"` text changes after its cassette was recorded, nothing at
runtime notices: `cli/explain.py` narrates the NEW prompt as "THE TASK" and
then prints the OLD recording's steps as what happened in response to it.
That breaks the module's own stated invariant -- "the narration is added by
wrapping those components, never by reimplementing them -- so if this prints
it, that is genuinely what happened."

Each cassette's `.meta.json` sidecar now carries the exact prompt it was
recorded against (`demo/cli/record.py` writes it; existing sidecars were
backfilled with the value that was actually in `TASKS[name]["say"]` at
record time, verified against git history). This is the guard that keeps a
future prompt edit from silently drifting away from its recording.
"""

from __future__ import annotations

import json
from pathlib import Path

from demo.cli.explain import TASKS

CASSETTES = Path(__file__).resolve().parents[2] / "demo" / "agent" / "cassettes"


def _sidecars() -> list[Path]:
    return sorted(CASSETTES.glob("*.meta.json"))


def test_there_are_cassette_sidecars_to_check():
    """A guard that silently checks nothing is not a guard."""
    assert _sidecars()


def test_every_sidecar_names_a_real_task_and_carries_a_prompt():
    for sidecar in _sidecars():
        meta = json.loads(sidecar.read_text())
        name = meta["task"]
        assert name in TASKS, f"{sidecar.name}: {name!r} is not a TASKS entry"
        assert meta.get("prompt"), (
            f"{sidecar.name} has no recorded 'prompt' -- cannot verify it still "
            f"matches TASKS[{name!r}]['say']; add it when recording "
            "(demo/cli/record.py)"
        )


def test_every_recorded_cassette_matches_its_declared_prompt():
    for sidecar in _sidecars():
        meta = json.loads(sidecar.read_text())
        name = meta["task"]
        assert meta["prompt"] == TASKS[name]["say"], (
            f"{name}: TASKS[{name!r}]['say'] no longer matches what "
            f"{sidecar.name} was recorded against -- either restore the old "
            "wording or re-record the cassette (demo/cli/record.py)"
        )


def test_every_task_with_its_own_cassette_has_a_checked_sidecar():
    """A scenario can get its own recording without ever wiring up the
    provenance check above -- this catches that gap rather than relying on
    every future recording to remember it."""
    checked_names = {json.loads(s.read_text())["task"] for s in _sidecars()}
    for name in TASKS:
        cassette = CASSETTES / f"{name}.json"
        if cassette.exists():
            assert name in checked_names, (
                f"{cassette.name} exists but has no .meta.json sidecar "
                "carrying the prompt it was recorded against"
            )
