# Bounding the live model call

**Status:** approved design, not yet implemented
**Occasioned by:** run `2026-08-02T12-27-53Z-explain-matrix-triage-live`, which
hung for 24 minutes on its tenth scenario and lost the nine that had finished.

## The problem

`explain --matrix --live` sat on scenario 10 (`crosscheck`) with no output and
no CPU for 24 minutes. It was not slow. It was blocked forever on a socket, and
nothing in the process was ever going to notice.

Four measurements, taken while it was still stuck:

- `utime`/`stime` identical when sampled 8 seconds apart. Single thread,
  state `S`. Nothing was computing.
- One `ESTAB` connection to `172.217.119.4:443` — in the DNS pool for
  `generativelanguage.googleapis.com` — with `Recv-Q 0`, `Send-Q 0` and **no
  timer of any kind**. The request went out, was acked, and no response ever
  came. With no keepalive the kernel will not notice a peer that went away.
- No `[llm]` line since the hang began. `ProgressFilter` forwards those to the
  real stdout and `_generate` prints *before* sleeping, so silence rules out a
  retry wait.
- Not blocked on stdin either: the only `input()` is gated on `PAUSE`, and menu
  option 9 passes no `--pause`.

### Cause one: the request has no deadline

`demo/agent/llm.py` builds its client as `genai.Client(api_key=api_key)`. No
`http_options`. Verified against the installed google-genai 2.15.0:

- `HttpOptions.timeout` defaults to `None`, and `_api_client.py` explicitly
  sets `args['timeout'] = None` on the httpx client when none is given.
  `timeout=None` in httpx means block forever.
- `retry_options` also defaults to `None`, which resolves to
  `stop_after_attempt(1), reraise=True`. The SDK does not retry, and it does
  not wrap the failure — a stall surfaces as a raw `httpx.TimeoutException`.

The retry loop in `_generate` cannot help here. It is a `try/except`, and a
request that never returns never raises. Its docstring says it is "bounded on
purpose: five attempts, each wait capped, so a genuine outage surfaces as an
error instead of hanging the demo" — that describes an intent the code does not
enforce. It bounds *error responses*, not *absent* ones.

Note the asymmetry this leaves: `OpenRouterClient` already passes
`httpx.Client(timeout=120.0)`. Only the Gemini path is unbounded.

### Cause two: the matrix holds every result in memory until the end

The loop appends to a local `rows` list and assigns `run.results` once, after
all ten scenarios. `run.model` is set after the loop too. So an interrupted
run writes a manifest with `results: {}` and `model: ""`, and the nine finished
scenarios are gone — the `.log` holds only their names.

That is what made this incident cost a full run rather than one scenario. The
protected side turned out to be partially recoverable by accident, because
each scenario's `tempfile.mkdtemp()` is never cleaned up and its `audit.jsonl`
survives in `/tmp`. The unprotected side was not: those numbers come from
in-memory sinks that `reset()` clears at the top of each scenario.

Recovering this particular run was considered and rejected — half a matrix is
not worth much as evidence. The fix is to not lose the next one.

## The design

### 1. Bound the request

Add `GEMINI_TIMEOUT_MS = 120_000` beside `GEMINI_MAX_TOKENS`, and pass it:

```python
from google import genai
from google.genai import types
client = genai.Client(
    api_key=api_key,
    http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
)
```

120 seconds matches the value `OpenRouterClient` already uses, so the two live
paths agree rather than each having its own number.

Both imports stay inside the existing lazy block. `google-genai` is
deliberately absent from `requirements.txt` and CI never installs it; an import
at module scope would break every test that imports this module.

### 2. Retry a timeout, on its own budget

`_generate` classifies a failure as transient by status code (429/500/503) or
by two substrings (`RESOURCE_EXHAUSTED`, `UNAVAILABLE`), and re-raises anything
else. An `httpx.ReadTimeout` matches none of those, so adding the timeout
without touching this would trade an infinite hang for a run that dies on the
first network blip. Both changes are required; neither is sufficient alone.

Timeouts get a **separate, smaller budget: 2 attempts**, tracked independently
of the existing 5. The reasoning is that the two failures carry different
information. A 429 is the expected case on a free tier, the server states how
long to wait, and waiting works. A stalled socket says nothing, costs the full
120 seconds to discover, and a connection that died once will usually die
again — five attempts would spend ten minutes proving it.

Worst case per turn, both bounded and visible:

| failure | attempts | worst case |
|---|---|---|
| 429 rate limit | 5, server-asked delays | ~5 min |
| stalled request | 2 × 120s + backoff | ~4 min |

One interaction worth stating, because the numbers above are per `_generate`
call and `next_step` can call it more than once. The empty-turn loop retries up
to three times, but only when `_generate` *returns*; an exhausted timeout
budget raises straight through it. So a turn that only ever stalls costs one
budget, and the pathological mix — empty turn, then stall, repeatedly — is the
only path that multiplies. That is bounded too, and it is loud, which is the
property the run that occasioned this design did not have.

The announcement is distinct, so a stall is not mistaken for a rate limit:

```
      [llm] request timed out after 120s, retrying
```

Exhausting the budget raises `RuntimeError("model stopped responding after
2 attempts")`. `httpx` is a hard dependency (`requirements.txt`), so
classifying on `httpx.TimeoutException` works in CI without the SDK present.

### 3. A failed scenario becomes a row, not the end of the run

Wrap the per-scenario body in `try/except`. On failure, append a row and carry
on to the next scenario:

```
  crosscheck      —            run failed: model timed out  not measured
```

`render_matrix` needs no change; every column it formats is already a string,
and the widths are computed with `max(len(...))` over whatever rows exist.

Any audit records the scenario did produce before failing are kept in the row's
`steps`, since that is real evidence of what the broker decided.

The failure also prints through `ProgressFilter` as it happens, so the operator
sees it during the run rather than only in the final table. A row that says
`run failed` is honest in a way that a silently missing row is not — a
nine-row matrix looks complete.

### 4. Save each scenario as it completes

Assign `run.results[name]` inside the loop instead of once after it, and set
`run.model` before the loop rather than after. `RunLog.__exit__` already runs
on exception, so an interrupted run then leaves a manifest holding every
scenario that finished, with the model that produced them.

Setting `run.model` early also drops a throwaway `_fresh_llm()` call that
existed only to read a client's name.

## Testing

Against the existing stub-client seam (`GeminiClient(..., client=...)`), so
none of these need the SDK or the network:

1. A stub raising `httpx.ReadTimeout` retries once, then raises `RuntimeError`
   — and prints the timeout line, not the rate-limit line.
2. A stub raising 429 still gets its five attempts. Regression: the new
   budget must not shrink the old one.
3. A scenario that raises produces a `run failed` row and the loop continues to
   the next scenario.
4. After an aborted matrix run, `run.results` holds the scenarios that
   completed and `run.model` is populated.
5. Client construction passes a bounded timeout, verified by injecting a fake
   `google.genai` into `sys.modules` so the assertion runs where the real SDK
   is absent.

## Out of scope

Recovering run `2026-08-02T12-27-53Z`. Adding an env var for the timeout — the
module's other model constants are plain literals and this one has no reason to
differ. Per-scenario or whole-run deadlines: the defect is an unbounded call,
and bounding the call is what fixes it.
