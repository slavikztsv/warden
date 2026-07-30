"""LLM access, recorded or live.

Cassettes replay MODEL RESPONSES ONLY. Policy decisions, network enforcement,
and the audit chain always execute for real — the cassette exists so the demo
cannot fail in the room, not to fake the result.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.tools import TOOL_SCHEMAS

ANTHROPIC_MODEL = "claude-sonnet-5"
GEMINI_MODEL = "gemini-3.6-flash"
MAX_TOKENS = 4096
# Gemini counts thinking against the output budget, and current models think by
# default. 4096 was enough to exhaust on reasoning alone and return a turn with
# neither text nor a function call, which the loop then read as "the agent is
# finished". Budget the live path separately.
GEMINI_MAX_TOKENS = 16384

# Kept for the Anthropic client, whose call site predates the second provider.
MODEL = ANTHROPIC_MODEL


class TracingLLM:
    """Wraps any LLM client and prints exactly what goes in and what comes back.

    The most common question about an agent is "what did you actually send it?",
    and answering that should not require a debugger. This wraps rather than
    instruments, so all three clients stay identical and the trace has the same
    shape whichever provider is in use — including the cassette, where it shows
    the conversation that *would* have been sent alongside the recorded reply.

    Enabled with WARDEN_TRACE=1. Off by default: the trace prints the full
    conversation, which includes whatever the agent has read.
    """

    def __init__(self, inner, limit: int = 900) -> None:
        self._inner = inner
        self._limit = limit
        self._turn = 0

    def _clip(self, text: str) -> str:
        text = str(text)
        if len(text) <= self._limit:
            return text
        return text[: self._limit] + f"\n      … [{len(text) - self._limit} more chars]"

    def next_step(self, messages: list[dict]) -> dict:
        self._turn += 1
        name = type(self._inner).__name__
        print(f"\n{'=' * 72}\n  TURN {self._turn}  —  asking {name}\n{'=' * 72}", flush=True)
        for i, message in enumerate(messages, 1):
            print(f"  [{i}] role={message.get('role')}", flush=True)
            print("      " + self._clip(message.get("content", "")).replace("\n", "\n      "), flush=True)

        step = self._inner.next_step(messages)

        print(f"  {'-' * 68}\n  MODEL REPLIED: type={step.get('type')}", flush=True)
        if step.get("type") == "tool_use":
            import json as _json

            print(f"      tool: {step['tool']}", flush=True)
            print("      args: " + self._clip(_json.dumps(step["args"])), flush=True)
        else:
            print("      text: " + self._clip(step.get("text", "")).replace("\n", "\n      "), flush=True)
        return step


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


class GeminiClient:
    """A second provider behind the same protocol, and that is the point.

    `run_task` is unchanged by this class existing. It asks an object for the
    next step and gets back `{"type": "tool_use", ...}` or `{"type": "final",
    ...}` — it cannot tell which vendor produced that, exactly as it cannot
    tell which dispatcher it holds. The enforcement layer is even further
    removed: the broker authorizes a tool call without knowing a model was
    involved at all.

    The shapes below were verified against google-genai 2.15.0 rather than
    written from memory:

      · tools go in as Tool(function_declarations=[FunctionDeclaration(...)]),
        and `parameters` accepts a plain JSON Schema dict — so the SAME
        TOOL_SCHEMAS the Anthropic path uses is translated mechanically, only
        the key name differs (`input_schema` there, `parameters` here).
      · a call comes back as a part carrying `.function_call` with `.name`,
        `.args` and `.id`.
      · the result goes back as a user turn holding
        Part.from_function_response(name=..., response={...}); Gemini matches
        on the function NAME, where Anthropic matches on a tool_use_id.
      · the model's own turn has role "model", not "assistant".

    As with the Anthropic client, `google-genai` is imported lazily and is
    deliberately absent from requirements.txt: the broker, the policy layer and
    all tests run without it, and CI never installs it. The tests drive this
    class through a stub, which pins the request shape and the turn
    alternation but cannot prove the live API accepts it.
    """

    def __init__(self, api_key: str, *, model: str | None = None, client=None) -> None:
        self._model = model or GEMINI_MODEL
        if client is None:
            from google import genai

            client = genai.Client(api_key=api_key)
        self._client = client
        self._history: list = []
        # Gemini returns SEVERAL function calls in one turn routinely, and the
        # agent loop executes one tool at a time. The extras queue here and are
        # served on later next_step calls without asking the model again.
        #
        # This class used to return the first call and drop the rest, which is a
        # protocol violation with a delayed and very confusing symptom: the
        # model's own turn is left holding a call that never receives a
        # response, and one or two turns later the reply degrades -- a stray
        # glyph, the call restated as prose, or an empty turn. Observed live as
        # "巾 eyes open: query_customers returned: ... Wait, was it returned in
        # the result?", which is the model asking where the dropped result went.
        self._pending_calls: list = []
        # Function responses accumulate until every call in the turn has been
        # answered, because Gemini expects the N responses to a multi-call turn
        # in ONE user turn, matched by function name.
        self._answered: list = []
        self._awaiting: str | None = None

    @staticmethod
    def _declarations():
        """One tool definition, two providers. Only the key name changes."""
        from google.genai import types

        return [
            types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name=schema["name"],
                        description=schema["description"],
                        parameters=schema["input_schema"],
                    )
                    for schema in TOOL_SCHEMAS
                ]
            )
        ]

    def _absorb(self, messages: list[dict]) -> None:
        from google.genai import types

        if not self._history:
            self._history.extend(
                types.Content(role="user", parts=[types.Part(text=m["content"])])
                for m in messages
            )
            return

        latest = messages[-1]["content"]
        if self._awaiting is not None:
            # Collected, not appended. An unanswered function call is a protocol
            # error, the same way an unanswered tool_use is on the Anthropic
            # side — and when the turn carried several calls, every response
            # belongs in the same user turn, so these accumulate until the last
            # queued call has been executed.
            self._answered.append(
                types.Part.from_function_response(
                    name=self._awaiting, response={"result": latest}
                )
            )
            self._awaiting = None
        else:
            self._history.append(
                types.Content(role="user", parts=[types.Part(text=latest)])
            )

    def _generate(self, config):
        """Retry a rate-limited turn, honouring the delay the server asks for.

        The free tier allows 5 requests per minute and this agent's task needs
        eight turns, so a 429 mid-run is the expected case rather than an edge
        one — an unretried live path would fail every time. 503 UNAVAILABLE is
        retried for the same reason: it was observed in practice, and it is the
        provider shedding load rather than anything wrong with the request.
        Bounded on purpose: five attempts, each wait capped, so a genuine outage
        surfaces as an error instead of hanging the demo.

        This flakiness is itself the argument for the cassette staying the
        default. A demo that depends on someone else's capacity is a demo that
        can fail in the room.

        Note this is not the "no blind retry" rule the broker follows for
        backends. That rule exists because retrying an authorized read
        amplifies it against a row bound. Nothing is authorized here: this is
        the agent talking to its own model, before any tool call exists.
        """
        import re
        import time as _time

        last = None
        for attempt in range(5):
            try:
                return self._client.models.generate_content(
                    model=self._model, contents=self._history, config=config
                )
            except Exception as exc:  # noqa: BLE001 - vendor error types vary
                text = str(exc)
                transient = (
                    getattr(exc, "code", None) in (429, 500, 503)
                    or "RESOURCE_EXHAUSTED" in text
                    or "UNAVAILABLE" in text
                )
                if not transient:
                    raise
                # A per-DAY quota does not clear within a run. Retrying it just
                # burns minutes before failing anyway, so surface it at once
                # with the fix in the message.
                if "PerDay" in text or "per day" in text:
                    raise RuntimeError(
                        "daily model quota exhausted for this model. Set "
                        "GEMINI_MODEL in .env to a different model, or wait for "
                        f"the quota to reset. Provider said: {text[:200]}"
                    ) from exc
                last = exc
                asked = re.search(r"retry in ([0-9.]+)s", text)
                delay = min(float(asked.group(1)) + 1 if asked else 2 ** attempt * 5, 65)
                print(f"[llm] transient provider error, waiting {delay:.0f}s", flush=True)
                _time.sleep(delay)
        raise RuntimeError(f"model still rate limited after 5 attempts: {last}")

    def _serve_queued(self) -> dict:
        """Hand the loop the next call the model asked for, oldest first."""
        call = self._pending_calls.pop(0)
        self._awaiting = call.name
        return {"type": "tool_use", "tool": call.name, "args": dict(call.args or {})}

    def next_step(self, messages: list[dict]) -> dict:
        from google.genai import types

        self._absorb(messages)

        # Serve a call the model already asked for before asking it for more.
        # No API call happens here: the model decided this in a previous turn,
        # and re-asking would both spend a turn and let it revise a sequence it
        # is midway through.
        if self._pending_calls:
            return self._serve_queued()

        # Every call in the previous turn has now been answered, so the
        # responses go back as one user turn, in the order the calls arrived.
        if self._answered:
            self._history.append(types.Content(role="user", parts=self._answered))
            self._answered = []

        config = types.GenerateContentConfig(
            tools=self._declarations(), max_output_tokens=GEMINI_MAX_TOKENS
        )

        # A turn carrying neither a call nor text is not the agent finishing —
        # it is an empty turn, seen intermittently in practice. Retry rather
        # than reporting a completion the model never signalled, and do NOT
        # append the empty turn: poisoning the history with it changes what the
        # model is answering on the retry, and a Content with no parts is
        # rejected outright on the next call.
        attempts = 3
        for attempt in range(1, attempts + 1):
            response = self._generate(config)
            candidate = response.candidates[0]
            parts = candidate.content.parts or []
            if any(
                getattr(part, "function_call", None) or getattr(part, "text", None)
                for part in parts
            ):
                # Appended verbatim: a reconstructed turn drops part types this
                # code does not model, and an edited history is rejected on the
                # next call.
                self._history.append(candidate.content)
                break
            # Only announce a retry when one actually follows. Printing this on
            # the final attempt reads as "it retried and I am still going",
            # which is the opposite of what happened.
            if attempt < attempts:
                print(f"[llm] empty turn {attempt}/{attempts}, retrying", flush=True)
        else:
            # No call and no text is NOT the agent finishing — it is a thinking
            # or truncated turn, and silently reporting it as `final` hides the
            # cause. finish_reason distinguishes them: MAX_TOKENS means the
            # output budget was consumed, STOP means the model ended its turn
            # having emitted only thought parts, which are not returned.
            reason = getattr(candidate, "finish_reason", None)
            return {
                "type": "final",
                "text": (
                    f"(no text and no tool call after {attempts} attempts; "
                    f"finish_reason={reason}. With STOP this is a thought-only "
                    f"turn — the model reasoned and emitted nothing. {self._model} "
                    "may be too small for this task; GEMINI_MODEL="
                    f"{GEMINI_MODEL} is the tested default.)"
                ),
            }

        # ALL of them, not just the first. See the note in __init__ on what
        # dropping the rest does to the next turn.
        self._pending_calls = [
            part.function_call
            for part in parts
            if getattr(part, "function_call", None) is not None
        ]
        if self._pending_calls:
            return self._serve_queued()

        text = "\n".join(
            part.text for part in parts if getattr(part, "text", None)
        )
        if text:
            return {"type": "final", "text": text}

        # Unreachable: the retry loop only breaks once some part carries a call
        # or text, so one of the two returns above has fired. Kept as a return
        # rather than a raise because falling off the end would hand the loop a
        # None to subscript, and a demo should degrade to a message.
        return {"type": "final", "text": "(unreachable: turn had neither call nor text)"}


def live_client_from_env(env: dict) -> object:
    """Pick a provider from whatever credential is present.

    Deliberately not a flag: the demo's default is the cassette, and `--live`
    should work with whichever key the operator actually has rather than
    forcing one vendor.
    """
    if env.get("GEMINI_API_KEY"):
        return GeminiClient(env["GEMINI_API_KEY"], model=env.get("GEMINI_MODEL") or None)
    if env.get("ANTHROPIC_API_KEY"):
        return LiveClient(env["ANTHROPIC_API_KEY"])
    raise RuntimeError(
        "--live needs GEMINI_API_KEY or ANTHROPIC_API_KEY in the environment. "
        "Without one, drop --live and the agent replays a cassette."
    )
