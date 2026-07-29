"""LLM access, recorded or live.

Cassettes replay MODEL RESPONSES ONLY. Policy decisions, network enforcement,
and the audit chain always execute for real — the cassette exists so the demo
cannot fail in the room, not to fake the result.
"""

from __future__ import annotations

import json
from pathlib import Path

MODEL = "claude-sonnet-5"


class Cassette:
    def __init__(self, path: Path) -> None:
        self._steps = json.loads(Path(path).read_text())
        self._index = 0

    def next_step(self, messages: list[dict]) -> dict:
        if self._index >= len(self._steps):
            return {"type": "final", "text": "cassette exhausted"}
        step = self._steps[self._index]
        self._index += 1
        return step


class LiveClient:
    """Used with --live. Kept deliberately small; the cassette is the default."""

    def __init__(self, api_key: str) -> None:
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key)

    def next_step(self, messages: list[dict]) -> dict:
        response = self._client.messages.create(
            model=MODEL, max_tokens=1024, messages=messages
        )
        for block in response.content:
            if block.type == "tool_use":
                return {"type": "tool_use", "tool": block.name, "args": block.input}
        return {"type": "final", "text": response.content[0].text}
