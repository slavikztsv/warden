"""LLM access, recorded or live.

Cassettes replay MODEL RESPONSES ONLY. Policy decisions, network enforcement,
and the audit chain always execute for real — the cassette exists so the demo
cannot fail in the room, not to fake the result.
"""

from __future__ import annotations

import json
from pathlib import Path

from demo.agent.tools import TOOL_SCHEMAS

GEMINI_MODEL = "gemini-3.6-flash"
# OpenRouter needs a vendor-qualified id. Override with OPENROUTER_MODEL;
# ids are listed at https://openrouter.ai/models and the client says so by
# name if the gateway does not recognise this one.
OPENROUTER_MODEL = "openai/gpt-4o-mini"
MAX_TOKENS = 4096
# Gemini counts thinking against the output budget, and current models think by
# default. 4096 was enough to exhaust on reasoning alone and return a turn with
# neither text nor a function call, which the loop then read as "the agent is
# finished". Budget the live path separately.
GEMINI_MAX_TOKENS = 16384

# A request with no deadline is a demo that can hang forever, and one did:
# google-genai defaults HttpOptions.timeout to None, httpx reads that as "wait
# indefinitely", and the SDK's own retry is off by default. 120s matches the
# value OpenRouterClient already passes, so the two live paths agree rather
# than each carrying its own number.
#
# This number is NOT only httpx's socket deadline. google-genai also forwards it
# to Google as the X-Server-Timeout header (see populate_server_timeout_header
# in google/genai/_api_client.py), so it is equally an instruction to the
# server: abandon the generation after this long. The server acts on it first --
# measured against the live API, a 10s value came back at 8.9s and a 45s value
# at 44.3s -- so a turn that overruns arrives as an HTTP 504 DEADLINE_EXCEEDED
# response, not as a stalled socket. _generate has to treat both as one event.
GEMINI_TIMEOUT_MS = 120_000

# A deadline overrun gets a smaller budget than a rate limit, on purpose. A 429
# is the expected case on a free tier, the server says how long to wait, and
# waiting works. An overrun carries no such instruction and costs up to the full
# deadline to discover.
#
# Three attempts rather than two: until 504 was recognised as an overrun this
# budget was unreachable -- the server's answer beat httpx's timeout every time,
# so the number here was never actually exercised. A matrix run makes several
# calls per scenario across several scenarios, and an overrun is the provider
# shedding load rather than a dead socket, so the retry usually lands in
# seconds: a healthy turn on this model measures 2-10s.
GEMINI_TIMEOUT_ATTEMPTS = 3
GEMINI_TIMEOUT_BACKOFF = 5.0


class TracingLLM:
    """Wraps any LLM client and prints exactly what goes in and what comes back.

    The most common question about an agent is "what did you actually send it?",
    and answering that should not require a debugger. This wraps rather than
    instruments, so every client stays identical and the trace has the same
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
        self.name = f"recorded — {Path(path).name}"

    @classmethod
    def from_steps(cls, steps: list[dict], label: str = "captured") -> "Cassette":
        """A cassette from a transcript in memory rather than from disk.

        Used to replay a live run through the other profile. A model cannot be
        sampled twice and asked to behave the same way, so the only controlled
        way to A/B one is to run it once and ask the counterfactual: given
        exactly what it did, what would the broker have done?
        """
        obj = cls.__new__(cls)
        obj._steps = list(steps)
        obj._index = 0
        obj.name = f"replay of a live run — {label}"
        return obj

    def next_step(self, messages: list[dict]) -> dict:
        if self._index >= len(self._steps):
            return {"type": "final", "text": "cassette exhausted"}
        step = self._steps[self._index]
        self._index += 1
        return step


class GeminiClient:
    """One of two providers behind the same protocol, and that is the point.

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
        TOOL_SCHEMAS the other client sends is translated mechanically, only
        the key name differs (`input_schema` in the catalogue, `parameters`
        here).
      · a call comes back as a part carrying `.function_call` with `.name`,
        `.args` and `.id`.
      · the result goes back as a user turn holding
        Part.from_function_response(name=..., response={...}); Gemini matches
        on the function NAME, where OpenRouter matches on a tool_call_id.
      · the model's own turn has role "model", not "assistant".

    `google-genai` is imported lazily and is deliberately absent from the
    default install -- it lives only in demo/pyproject.toml's `live` extra and
    requirements-live.txt, so the broker, the policy layer and all tests run
    without it, and CI never installs it. The tests drive this
    class through a stub, which pins the request shape and the turn
    alternation but cannot prove the live API accepts it.
    """

    def __init__(self, api_key: str, *, model: str | None = None, client=None) -> None:
        self._model = model or GEMINI_MODEL
        self.name = f"gemini:{self._model}"
        if client is None:
            from google import genai
            from google.genai import types

            client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
            )
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
            # error, the same way an unanswered tool_call is on the OpenRouter
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

        That bound covered error RESPONSES, not absent ones. A request that
        never returns never raises, so until the client was given a deadline
        this loop could not see the failure it claimed to bound — a live matrix
        run hung on one socket for 24 minutes. An overrun now lands in its own
        branch with its own, smaller budget.

        Giving the client a deadline then moved the failure rather than ending
        it. GEMINI_TIMEOUT_MS is sent to Google as X-Server-Timeout too, so the
        server abandons an overlong generation and answers 504 DEADLINE_EXCEEDED
        just before httpx would have stalled — turning the silent case into a
        loud one, which this method was not reading. Every scenario of the
        2026-08-02 live matrix reported "run failed: 504 DEADLINE_EXCEEDED" for
        that reason, and none of them had anything wrong with the request.
        """
        import re
        import time as _time

        import httpx

        last = None
        attempt = 0   # transient provider errors: 429/500/502/503
        timeouts = 0  # deadline overruns, budgeted separately
        while attempt < 5:
            try:
                return self._client.models.generate_content(
                    model=self._model, contents=self._history, config=config
                )
            except Exception as exc:
                text = str(exc)
                code = getattr(exc, "code", None)

                # A deadline overrun, in both the shapes it arrives in. The
                # stalled socket is what GEMINI_TIMEOUT_MS was written for; the
                # 504 is the SAME event reported by the server, which was told
                # the same deadline via X-Server-Timeout and nearly always
                # answers before httpx gives up. Handling only the first shape
                # is what made every scenario of the 2026-08-02 live matrix run
                # die: a 504 fell through to the transient test below, did not
                # match it, and re-raised on the very first occurrence.
                #
                # httpx.ConnectError is deliberately still excluded: it fails
                # fast and says something specific, where this is the silent
                # case the deadline exists for.
                if (
                    isinstance(exc, httpx.TimeoutException)
                    or code == 504
                    or "DEADLINE_EXCEEDED" in text
                ):
                    timeouts += 1
                    if timeouts >= GEMINI_TIMEOUT_ATTEMPTS:
                        raise RuntimeError(
                            "model did not finish a turn within "
                            f"{GEMINI_TIMEOUT_MS // 1000}s, {timeouts} times "
                            "running. The request was accepted and the "
                            "generation was abandoned at the deadline."
                        ) from exc
                    print(
                        f"[llm] turn exceeded {GEMINI_TIMEOUT_MS // 1000}s, "
                        "retrying",
                        flush=True,
                    )
                    _time.sleep(GEMINI_TIMEOUT_BACKOFF)
                    # An overrun does not spend a rate-limit attempt: the two
                    # budgets count different failures.
                    continue

                transient = (
                    code in (429, 500, 502, 503)
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
                attempt += 1
        raise RuntimeError(f"model still rate limited after {attempt} attempts: {last}")

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


class OpenRouterClient:
    """The second provider behind the same protocol — one key, many vendors.

    OpenRouter speaks the OpenAI chat-completions shape, which is plain JSON
    over HTTP, so this talks to it with `httpx` and adds NO dependency. That is
    worth more than convenience: `google-genai` is confined to demo's `live`
    extra on purpose, so the other live client cannot be
    exercised in CI. This one can be, and is — the provider with no SDK is the
    only one with real test coverage.

    It also turns the model into a variable rather than a rewrite. The finding
    that a more capable model works harder around a refusal and still cannot
    exceed the bound is a claim about models in general. One key that reaches
    dozens of them is how you check that rather than assert it:

        OPENROUTER_MODEL=anthropic/claude-sonnet-4.5 warden-demo explain --live --task report
        OPENROUTER_MODEL=openai/gpt-4o-mini          warden-demo explain --live --task report

    Shape notes, verified against the OpenAI-compatible schema rather than
    written from memory:
      · tools go in as {"type":"function","function":{name,description,parameters}}
      · a call comes back as choices[0].message.tool_calls[], each with an `id`
        and `function.arguments` as a JSON *string*, not an object
      · the answer goes back as its own {"role":"tool","tool_call_id":…} message,
        one per call — unlike Gemini, which wants them combined in one turn
    """

    URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(
        self,
        api_key: str,
        *,
        model: str | None = None,
        client=None,
        url: str | None = None,
        retries: int = 5,
        max_delay: float = 65.0,
    ) -> None:
        import httpx

        # A sweep across many models wants a short retry budget: a 429 from a
        # busy free-tier model is a fact about that model's availability, not a
        # transient blip worth five escalating waits. A single live run wants
        # the opposite, so it stays the default.
        self._retries = max(1, retries)
        self._max_delay = max_delay
        self._key = api_key
        self._model = model or OPENROUTER_MODEL
        self._url = url or self.URL
        self._client = client or httpx.Client(timeout=120.0)
        self.name = f"openrouter:{self._model}"
        self._history: list[dict] = []
        # Same queue as GeminiClient, and for the same reason: a turn may carry
        # several calls, the loop executes one at a time, and dropping the rest
        # leaves the model's own turn holding a call that never gets answered.
        self._pending_calls: list[dict] = []
        self._awaiting: str | None = None

    @staticmethod
    def _tools() -> list[dict]:
        """One tool definition, either provider. Only the wrapper changes."""
        return [
            {
                "type": "function",
                "function": {
                    "name": schema["name"],
                    "description": schema["description"],
                    "parameters": schema["input_schema"],
                },
            }
            for schema in TOOL_SCHEMAS
        ]

    def _absorb(self, messages: list[dict]) -> None:
        if not self._history:
            self._history.extend(
                {"role": "user", "content": m["content"]} for m in messages
            )
            return

        latest = messages[-1]["content"]
        if self._awaiting is not None:
            # An unanswered tool call is a protocol error here as much as it is
            # on the other two providers. Each answer is its own message, keyed
            # by the call's id.
            self._history.append(
                {"role": "tool", "tool_call_id": self._awaiting, "content": latest}
            )
            self._awaiting = None
        else:
            self._history.append({"role": "user", "content": latest})

    def _post(self, body: dict) -> dict:
        """One request, retrying only what is worth retrying.

        Same reasoning as the Gemini path: rate limits and 5xx are the expected
        case on a shared gateway, and an unretried live run fails constantly.
        A 401 or an unknown model are not transient and must surface at once
        with the fix in the message.
        """
        import re
        import time as _time


        last = None
        for attempt in range(self._retries):
            response = self._client.post(
                self._url,
                headers={
                    "Authorization": f"Bearer {self._key}",
                    "Content-Type": "application/json",
                    # OpenRouter attributes traffic with these. Harmless, and
                    # it keeps the request identifiable in the dashboard.
                    "HTTP-Referer": "https://github.com/slavikztsv/warden",
                    "X-Title": "warden agent security broker",
                },
                json=body,
            )
            if response.status_code == 200:
                payload = response.json()
                # OpenRouter can answer 200 with an error body when an upstream
                # provider fails. Treating that as success yields a confusing
                # KeyError on 'choices' several frames away.
                if "error" in payload and "choices" not in payload:
                    raise RuntimeError(
                        f"openrouter returned an error for {self._model}: "
                        f"{str(payload['error'])[:300]}"
                    )
                return payload

            text = response.text[:400]
            if response.status_code in (401, 403):
                raise RuntimeError(
                    "openrouter rejected the credential. Check OPENROUTER_API_KEY "
                    f"in .env. Provider said: {text}"
                )
            if response.status_code in (400, 404) and "model" in text.lower():
                raise RuntimeError(
                    f"openrouter does not recognise the model {self._model!r}. Set "
                    "OPENROUTER_MODEL in .env to an id from https://openrouter.ai/models "
                    f"(for example openai/gpt-4o-mini). Provider said: {text}"
                )
            if response.status_code not in (408, 409, 429, 500, 502, 503, 504):
                raise RuntimeError(
                    f"openrouter returned {response.status_code}: {text}"
                )

            last = f"{response.status_code}: {text}"
            asked = response.headers.get("retry-after")
            if attempt == self._retries - 1:
                break
            if asked and re.fullmatch(r"\d+", asked.strip()):
                delay = min(float(asked) + 1, self._max_delay)
            else:
                delay = min(2 ** attempt * 5, self._max_delay)
            print(
                f"[llm] openrouter {response.status_code}, waiting {delay:.0f}s",
                flush=True,
            )
            _time.sleep(delay)
        raise RuntimeError(
            f"openrouter still failing after {self._retries} attempts: {last}"
        )

    def _serve_queued(self) -> dict:
        call = self._pending_calls.pop(0)
        self._awaiting = call["id"]
        function = call.get("function") or {}
        raw = function.get("arguments") or "{}"
        try:
            args = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except (ValueError, TypeError):
            # Left as {} rather than guessed at. The broker validates the shape
            # of every call, so a malformed one is refused by `input.malformed`
            # -- which is the correct outcome and visible in the audit log,
            # where a silently repaired call would not be.
            print(f"[llm] unparseable arguments for {function.get('name')}", flush=True)
            args = {}
        if not isinstance(args, dict):
            args = {}
        return {"type": "tool_use", "tool": function.get("name"), "args": args}

    def next_step(self, messages: list[dict]) -> dict:
        self._absorb(messages)

        if self._pending_calls:
            return self._serve_queued()

        body = {
            "model": self._model,
            "messages": self._history,
            "tools": self._tools(),
            "tool_choice": "auto",
            "max_tokens": MAX_TOKENS,
        }

        attempts = 3
        for attempt in range(1, attempts + 1):
            payload = self._post(body)
            choices = payload.get("choices") or []
            if not choices:
                message, finish = {}, "no choices"
            else:
                message = choices[0].get("message") or {}
                finish = choices[0].get("finish_reason")
            calls = message.get("tool_calls") or []
            text = message.get("content") or ""
            if calls or text.strip():
                # Appended as returned. A reconstructed assistant turn drops
                # fields the API validates on the next request.
                self._history.append(message)
                break
            if attempt < attempts:
                print(f"[llm] empty turn {attempt}/{attempts}, retrying", flush=True)
        else:
            return {
                "type": "final",
                "text": (
                    f"(no text and no tool call after {attempts} attempts; "
                    f"finish_reason={finish}. {self._model} may not support tool "
                    "calling on OpenRouter — check the model's page, or set "
                    "OPENROUTER_MODEL to one that lists 'tools' support.)"
                ),
            }

        if calls:
            self._pending_calls = list(calls)
            return self._serve_queued()
        return {"type": "final", "text": text}


def live_client_from_env(env: dict) -> object:
    """Pick a provider from whatever credential is present.

    Deliberately not a flag: the demo's default is the cassette, and `--live`
    should work with whichever key the operator actually has rather than
    forcing one vendor.

    Precedence is fixed and documented rather than clever, and
    `WARDEN_PROVIDER` overrides it outright — a machine with several keys
    should never leave you guessing which one a run used. Every client also
    carries a `name`, which the runner prints, so the answer is on screen.
    """
    providers = {
        "openrouter": lambda: OpenRouterClient(
            env["OPENROUTER_API_KEY"], model=env.get("OPENROUTER_MODEL") or None
        ),
        "gemini": lambda: GeminiClient(
            env["GEMINI_API_KEY"], model=env.get("GEMINI_MODEL") or None
        ),
    }
    keys = {
        "openrouter": "OPENROUTER_API_KEY",
        "gemini": "GEMINI_API_KEY",
    }

    forced = (env.get("WARDEN_PROVIDER") or "").strip().lower()
    if forced:
        if forced not in providers:
            raise RuntimeError(
                f"WARDEN_PROVIDER={forced!r} is not one of: "
                f"{', '.join(providers)}."
            )
        if not env.get(keys[forced]):
            raise RuntimeError(
                f"WARDEN_PROVIDER={forced} needs {keys[forced]} in the environment."
            )
        return providers[forced]()

    for name in ("openrouter", "gemini"):
        if env.get(keys[name]):
            return providers[name]()

    raise RuntimeError(
        "--live needs either OPENROUTER_API_KEY or GEMINI_API_KEY in the "
        "environment. Without one, drop --live and the agent replays a "
        "cassette."
    )
