"""The demo's scenario, loaded once from `task.toml`.

`[task]` mirrors the grant `cli/explain.py` mints for the guarded run --
`agent_id`, `task_id`, `purpose` are the exact three fields the frozen
`tests/golden/audit-4711.jsonl` recorded from a real run, and
`tests/demo/test_scenario_config.py` asserts the two cannot drift apart.
`[scenario]` names the seeded row count, which of the four poison payloads is
active, where the documents that carry them live on disk, and which hostname
the mock transport treats as the exfiltration sink. `[prompts]` holds the
handful of TASKS strings in `cli/explain.py` that are shared verbatim by
several scenarios, or that are recorded evidence in a cassette and must not
change -- see the comment above `[prompts]` in task.toml for why.

Every module that used to hardcode a piece of this -- `agent/loop.py`'s
SYSTEM_TASK, `mocks/docstore.py`'s TICKET/POISONS, `mocks/seed_db.py`'s
default row count, `cli/explain.py`'s restated prompts and mock-transport
hostname -- reads it from here instead, so there is exactly one place that
knows what the scenario is.
"""

from __future__ import annotations

import tomllib

from demo.scenario.paths import REPO_ROOT, TASK_TOML

_config = tomllib.loads(TASK_TOML.read_text())

TASK: dict = _config["task"]
SCENARIO: dict = _config["scenario"]
PROMPTS: dict = _config["prompts"]

PROMPT: str = TASK["prompt"]
DOCUMENTS_ROOT = REPO_ROOT / SCENARIO["documents"]
