"""LLM access, recorded or live.

Cassettes replay MODEL RESPONSES ONLY. Policy decisions, network enforcement,
and the audit chain always execute for real — the cassette exists so the demo
cannot fail in the room, not to fake the result.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.tools import TOOL_SCHEMAS

MODEL = "claude-sonnet-5"
MAX_TOKENS = 4096


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
    """Used with --live. Kept deliberately small; the cassette is the default.

    This class previously could not work at all: `next_step` called
    `messages.create` without a `tools=` argument, so the model was never told
    any tools existed, no `tool_use` block could ever come back, and every turn
    returned `final` on the first response. `--live` is the project's answer to
    "is this canned?", and an answer that silently degrades to a single text
    turn is worse than no answer.

    Two conversations exist, and conflating them was the other half of the
    problem. agent/loop.py keeps a simple transcript — one user message per
    tool result — because that is all the cassette path needs. The Messages API
    needs something stricter: the assistant turn carrying the `tool_use` block
    must be echoed back verbatim, and the result must return as a `tool_result`
    block whose `tool_use_id` matches. This class therefore keeps its own
    API-shaped history and maps the loop's latest message onto it, so the loop
    stays byte-identical across both profiles and both LLM sources.

    The `anthropic` import stays lazy and the package is deliberately NOT in
    requirements.txt: the broker, the policy layer, and every test run without
    it. **This path is not exercised by any test that talks to the real API,
    and CI never installs the package** — the tests below drive it through a
    stub client, which pins the request shape and the message alternation but
    cannot prove the live API accepts it.
    """

    def __init__(self, api_key: str, *, client=None) -> None:
        if client is None:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key)
        self._client = client
        # Messages in Anthropic API shape, which is NOT the loop's shape.
        self._history: list[dict] = []
        self._pending_tool_use_id: str | None = None

    def _absorb(self, messages: list[dict]) -> None:
        """Folds the loop's latest turn into the API-shaped history.

        First call: seed from whatever the loop has (normally the single task
        message). Later calls: the loop has appended exactly one message, the
        JSON-encoded result of the tool call we returned last time. If that
        call was a tool_use, the result MUST come back as a tool_result block
        carrying the same id -- the API rejects a tool_use turn that is not
        answered, and mismatched ids are how that silently goes wrong.
        """
        if not self._history:
            self._history.extend(
                {"role": message["role"], "content": message["content"]}
                for message in messages
            )
            return

        latest = messages[-1]["content"]
        if self._pending_tool_use_id is not None:
            self._history.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": self._pending_tool_use_id,
                            "content": latest,
                        }
                    ],
                }
            )
            self._pending_tool_use_id = None
        else:
            self._history.append({"role": "user", "content": latest})

    def next_step(self, messages: list[dict]) -> dict:
        self._absorb(messages)

        response = self._client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            tools=TOOL_SCHEMAS,
            messages=self._history,
        )

        # The assistant turn goes back verbatim -- content blocks are appended
        # as returned, not reconstructed. Reconstructing drops block types this
        # code does not know about (thinking blocks among them, which carry a
        # signature the API validates), and an edited assistant turn is
        # rejected on the next request.
        self._history.append({"role": "assistant", "content": response.content})

        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                self._pending_tool_use_id = block.id
                return {"type": "tool_use", "tool": block.name, "args": block.input}

        text = "\n".join(
            block.text
            for block in response.content
            if getattr(block, "type", None) == "text"
        )
        return {"type": "final", "text": text}
