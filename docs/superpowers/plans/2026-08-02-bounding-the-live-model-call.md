# Bounding the Live Model Call — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A live `explain --matrix` run can no longer hang forever on one model call, and an interrupted one no longer loses the scenarios that finished.

**Architecture:** Five changes across three files. `demo/agent/llm.py` gains a request deadline and a separate retry budget for a stalled request. `demo/cli/explain.py` extracts the matrix loop's body so a failing scenario can be caught and turned into a row instead of ending the run, and records each row as it completes. `demo/cli/runlog.py` captures the git commit at the start of a run instead of the end.

**Tech Stack:** Python 3.12, pytest, httpx 0.28.1, google-genai 2.15.0 (optional at runtime, absent in CI).

**Spec:** [`docs/superpowers/specs/2026-08-02-bounding-the-live-model-call-design.md`](../specs/2026-08-02-bounding-the-live-model-call-design.md)

## Global Constraints

- `google-genai` is deliberately absent from `requirements.txt` and CI never installs it. Every `google.genai` import stays inside a function body, never at module scope. Tests that need the real SDK begin with `pytest.importorskip("google.genai")`.
- `httpx` IS a hard dependency (`requirements.txt:12`, pinned `0.28.1`). Importing it in `demo/agent/llm.py` is safe and works in CI.
- Timeout value is `120_000` ms, matching the `httpx.Client(timeout=120.0)` that `OpenRouterClient` already uses (`demo/agent/llm.py:512`).
- Stalled-request budget is **2 attempts total** (one retry). The existing 429/500/503 budget of **5 attempts** must not shrink.
- Run tests with `.venv/bin/python -m pytest`. `pytest.ini` sets `--import-mode=importlib`; do not add `pythonpath`.
- Do not reformat or rewrap comments you are not changing. This codebase's comments carry the reasoning and are load-bearing.

---

### Task 1: Bound the Gemini request

**Files:**
- Modify: `demo/agent/llm.py:26` (constants), `demo/agent/llm.py:240-247` (`GeminiClient.__init__`)
- Test: `tests/demo/test_agent.py` (append to the GeminiClient section, after line 532)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: module constant `GEMINI_TIMEOUT_MS: int = 120_000`, used by Task 2.

- [ ] **Step 1: Write the failing test**

Append to `tests/demo/test_agent.py`:

```python
def test_the_gemini_client_is_built_with_a_bounded_request_timeout(monkeypatch):
    """A client built without http_options waits forever.

    google-genai defaults HttpOptions.timeout to None, which reaches httpx as
    timeout=None, and its default retry_options resolve to stop_after_attempt(1)
    — so a stalled response is never retried and never abandoned. A live matrix
    run blocked on one socket for 24 minutes with no CPU and no output, and
    nothing in the process was going to notice.
    """
    pytest.importorskip("google.genai")
    from google import genai

    from demo.agent.llm import GEMINI_TIMEOUT_MS, GeminiClient

    seen = {}

    def recorder(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(models=None)

    monkeypatch.setattr(genai, "Client", recorder)
    GeminiClient("key")

    assert GEMINI_TIMEOUT_MS == 120_000, "must match OpenRouterClient's 120.0s"
    assert seen["http_options"].timeout == GEMINI_TIMEOUT_MS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/demo/test_agent.py::test_the_gemini_client_is_built_with_a_bounded_request_timeout -v`

Expected: FAIL with `ImportError: cannot import name 'GEMINI_TIMEOUT_MS'`.

(If it reports SKIPPED, `google-genai` is not installed in this environment. Install it with `.venv/bin/pip install google-genai==2.15.0` — it is in `requirements-live.txt` — or note the skip and rely on Task 2's tests, which need no SDK.)

- [ ] **Step 3: Add the constant**

In `demo/agent/llm.py`, immediately after `GEMINI_MAX_TOKENS = 16384` (line 26):

```python
# A request with no deadline is a demo that can hang forever, and one did:
# google-genai defaults HttpOptions.timeout to None, httpx reads that as "wait
# indefinitely", and the SDK's own retry is off by default. 120s matches the
# value OpenRouterClient already passes, so the two live paths agree rather
# than each carrying its own number.
GEMINI_TIMEOUT_MS = 120_000
```

- [ ] **Step 4: Pass it to the client**

In `demo/agent/llm.py`, replace lines 243-246:

```python
        if client is None:
            from google import genai

            client = genai.Client(api_key=api_key)
```

with:

```python
        if client is None:
            from google import genai
            from google.genai import types

            client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
            )
```

Both imports stay inside the `if` — see Global Constraints.

- [ ] **Step 5: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/demo/test_agent.py -v -k gemini`

Expected: PASS, and the four pre-existing gemini tests still pass.

- [ ] **Step 6: Commit**

```bash
git add demo/agent/llm.py tests/demo/test_agent.py
git commit -m "fix: give the Gemini request a deadline

google-genai defaults HttpOptions.timeout to None, which httpx reads as
'wait forever', and its default retry_options resolve to a single attempt.
A live matrix run blocked on one socket for 24 minutes: no CPU, no output,
and an ESTAB connection with no timer of any kind."
```

---

### Task 2: Retry a stalled request on its own budget

**Files:**
- Modify: `demo/agent/llm.py:26` (two more constants), `demo/agent/llm.py:333-365` (`GeminiClient._generate`)
- Test: `tests/demo/test_agent.py` (append after Task 1's test)

**Interfaces:**
- Consumes: `GEMINI_TIMEOUT_MS` from Task 1.
- Produces: constants `GEMINI_TIMEOUT_ATTEMPTS: int = 2` and `GEMINI_TIMEOUT_BACKOFF: float = 5.0`. `_generate` raises `RuntimeError` whose message contains `"stopped responding"` when the timeout budget is exhausted. Nothing later depends on these.

**Why both this and Task 1 are required:** `_generate` classifies a failure as transient by status code or by the substrings `RESOURCE_EXHAUSTED` / `UNAVAILABLE`, and re-raises anything else. An `httpx.ReadTimeout` matches none of them. Task 1 alone would trade an infinite hang for a run that dies on the first network blip.

- [ ] **Step 1: Write the failing tests**

Append to `tests/demo/test_agent.py`:

```python
def _raising_gemini_stub(exc):
    """A client whose every generate_content call raises `exc`."""
    calls = []

    class Models:
        def generate_content(self, **kwargs):
            calls.append(kwargs)
            raise exc

    return SimpleNamespace(models=Models()), calls


def test_a_stalled_request_is_retried_once_and_then_abandoned(monkeypatch, capsys):
    """A stall gets a smaller budget than a rate limit, and says which it was.

    A 429 is the expected case on a free tier, the server states how long to
    wait, and waiting works. A stalled socket says nothing, costs the full
    120s to discover, and a connection that died once usually dies again —
    five attempts would spend ten minutes proving it.
    """
    import time

    import httpx

    from demo.agent.llm import GeminiClient

    waits = []
    monkeypatch.setattr(time, "sleep", waits.append)
    stub, calls = _raising_gemini_stub(httpx.ReadTimeout("timed out"))

    with pytest.raises(RuntimeError, match="stopped responding"):
        GeminiClient("key", client=stub)._generate(config=None)

    assert len(calls) == 2, "two attempts total, not the rate-limit budget of five"
    assert waits == [5.0], "one backoff, between the two attempts"
    out = capsys.readouterr().out
    assert "[llm] request timed out after 120s, retrying" in out
    # A stall must not be announced as a rate limit -- they call for different
    # operator responses, and the wait line is the only thing on screen.
    assert "transient provider error" not in out


def test_a_rate_limit_still_gets_its_five_attempts(monkeypatch, capsys):
    """Regression: the timeout budget must not shrink the existing one."""
    import time

    from demo.agent.llm import GeminiClient

    monkeypatch.setattr(time, "sleep", lambda _: None)
    stub, calls = _raising_gemini_stub(Exception("429 RESOURCE_EXHAUSTED"))

    with pytest.raises(RuntimeError, match="still rate limited"):
        GeminiClient("key", client=stub)._generate(config=None)

    assert len(calls) == 5
    assert "[llm] transient provider error" in capsys.readouterr().out


def test_a_non_transient_error_is_not_retried_at_all(monkeypatch):
    """Regression: only transient failures are worth a second attempt."""
    from demo.agent.llm import GeminiClient

    stub, calls = _raising_gemini_stub(ValueError("malformed request"))

    with pytest.raises(ValueError, match="malformed request"):
        GeminiClient("key", client=stub)._generate(config=None)

    assert len(calls) == 1
```

Note these need no `importorskip`: `_generate` imports only `re`, `time` and `httpx`, and `GeminiClient.__init__` skips the SDK entirely when a `client` is passed. They run in CI.

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/demo/test_agent.py -v -k "stalled or rate_limit or non_transient"`

Expected: the stalled test FAILS (a `ReadTimeout` is re-raised unretried, so `RuntimeError` is never raised). The other two should already PASS — they pin behaviour Task 2 must preserve.

- [ ] **Step 3: Add the two constants**

In `demo/agent/llm.py`, directly below `GEMINI_TIMEOUT_MS`:

```python
# A stall gets a smaller budget than a rate limit, on purpose. A 429 is the
# expected case on a free tier, the server says how long to wait, and waiting
# works. A stalled socket carries no information, costs the full timeout to
# discover, and a connection that died once will usually die again.
GEMINI_TIMEOUT_ATTEMPTS = 2
GEMINI_TIMEOUT_BACKOFF = 5.0
```

- [ ] **Step 4: Rewrite the retry loop**

In `demo/agent/llm.py`, replace the body of `_generate` below its docstring (lines 333-365) with:

```python
        import re
        import time as _time

        import httpx

        last = None
        attempt = 0   # transient provider errors: 429/500/503
        timeouts = 0  # stalled requests, budgeted separately
        while attempt < 5:
            try:
                return self._client.models.generate_content(
                    model=self._model, contents=self._history, config=config
                )
            except httpx.TimeoutException as exc:
                # Deliberately NOT httpx.ConnectError: that fails fast and says
                # something specific, where this is the silent case the whole
                # deadline exists for.
                timeouts += 1
                if timeouts >= GEMINI_TIMEOUT_ATTEMPTS:
                    raise RuntimeError(
                        f"model stopped responding after {timeouts} attempts "
                        f"of {GEMINI_TIMEOUT_MS // 1000}s each. The request was "
                        "accepted and no response came back."
                    ) from exc
                print(
                    f"[llm] request timed out after {GEMINI_TIMEOUT_MS // 1000}s,"
                    " retrying",
                    flush=True,
                )
                _time.sleep(GEMINI_TIMEOUT_BACKOFF)
                # A stall does not spend a rate-limit attempt: the two budgets
                # count different failures.
                continue
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
                attempt += 1
        raise RuntimeError(f"model still rate limited after {attempt} attempts: {last}")
```

Two details that matter. `httpx.TimeoutException` must be caught **before** the bare `except Exception`, since it is a subclass. And `attempt` is incremented at the end of its branch, so `2 ** attempt * 5` still yields 5 on the first failure exactly as the `for attempt in range(5)` version did.

- [ ] **Step 5: Extend the docstring**

The existing docstring at `demo/agent/llm.py:314-332` claims the loop is "bounded on purpose ... so a genuine outage surfaces as an error instead of hanging the demo". That was not true of a stall. Append a paragraph before the closing `"""`:

```
        That bound covered error RESPONSES, not absent ones. A request that
        never returns never raises, so until the client was given a deadline
        this loop could not see the failure it claimed to bound — a live matrix
        run hung on one socket for 24 minutes. A stall now lands in its own
        branch with its own, smaller budget.
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/demo/test_agent.py -v`

Expected: PASS, all tests in the file, including the four pre-existing gemini tests.

- [ ] **Step 7: Commit**

```bash
git add demo/agent/llm.py tests/demo/test_agent.py
git commit -m "fix: retry a stalled model request on its own budget

A ReadTimeout matches none of _generate's transient tests, so the deadline
added in the previous commit would have killed a run on the first blip.
Timeouts get 2 attempts where a 429 gets 5: a 429 says how long to wait and
waiting works, where a stall says nothing and costs 120s to discover."
```

---

### Task 3: Extract the matrix row builder

**Files:**
- Modify: `demo/cli/explain.py:1287-1383` (the matrix loop)
- Test: none new — this task changes no behaviour and is guarded by the existing suite.

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: two module-level functions that Task 4 uses:
  - `_steps_from(scratch: Path) -> list[dict]`
  - `_matrix_row(name: str, spec: dict, db: Path, live: bool, scratch: Path, reset) -> dict`

**Why:** Task 4 needs to wrap the loop body in `try/except`. The body currently contains its own `continue` and two separate `rows.append(...)` sites, so wrapping it in place would leave the catch and the two success paths tangled — and there would be two places to also record `run.results`. Extracting first makes Task 4 a four-line change and makes the row-building testable without running ten scenarios.

- [ ] **Step 1: Add the two helpers**

In `demo/cli/explain.py`, insert directly above `def render_matrix(` (line 1147):

```python
def _steps_from(scratch: Path) -> list[dict]:
    """The per-call decisions a protected run recorded, if it got that far.

    "43 refused" is a summary; which calls, against what, and under which rule
    is the part a reader can check. Returns [] when the run failed before the
    broker wrote anything, which is a fact about the run, not an error.
    """
    audit_file = scratch / "audit.jsonl"
    if not audit_file.exists():
        return []
    return [
        {
            "n": record["seq"],
            "tool": record["action"]["tool"],
            "target": _target_label(record["target"]),
            "decision": record["decision"],
            "rule": record["rule"],
            "held": list(record["task_state"]["data_classes_held"]),
            "rows_before": record["task_state"]["rows_returned_so_far"],
        }
        for record in AuditLog(audit_file).records()
    ]


def _matrix_row(
    name: str, spec: dict, db: Path, live: bool, scratch: Path, reset
) -> dict:
    """One scenario's A/B, measured. Raises if either profile fails.

    Extracted from the matrix loop so a failing scenario can be caught without
    the catch swallowing the loop's own control flow, and so this is testable
    without running every scenario end to end.
    """
    pair = (name, spec)
    captured: list = []
    reset()
    docstore.set_poison(spec.get("poison", "backup"))
    un = _run_unprotected(db, _fresh_llm(live, pair), live, pair, capture=captured)
    reset()
    docstore.set_poison(spec.get("poison", "backup"))
    # THE POINT. With --live the unprotected side is a real model, and
    # the protected side replays exactly what it just did. Sampling the
    # model a second time would let it take a different path, and the
    # comparison would silently stop being about the broker -- which
    # is not hypothetical: inject-vendor once leaked 119 bytes
    # unprotected and recorded zero refusals protected, in one command.
    protected_llm = (
        Cassette.from_steps(captured, name) if live
        else _fresh_llm(False, pair)
    )
    gu = _run_protected(scratch, db, protected_llm, pair)

    steps = _steps_from(scratch)
    harms = [
        (f"{un['customer records read']:,} records read", "customer records read"),
        (f"{un['bytes that left']} bytes out", "bytes that left"),
        (f"{un['PII into internal systems']} bytes filed internally",
         "PII into internal systems"),
        (f"{un['mail to undeclared recipients']} misdirected email",
         "mail to undeclared recipients"),
    ]
    worst = max(harms, key=lambda h: un[h[1]] if h[1] != "customer records read"
                else un[h[1]] - 1)
    if gu["tool calls refused"] == 0:
        # The model never asked for anything out of scope, so there was
        # nothing to refuse. Falling through to the harm columns would
        # print the LEGITIMATE email as damage the broker failed to
        # stop, which is the opposite of what happened.
        return {
            "steps": steps,
            "scenario": name,
            "rule": "—",
            "harm": "model declined the instruction",
            "protected": "nothing to refuse",
            "note": spec["damage"],
        }
    if all(un[key] == 0 for _, key in harms[1:]) and un[harms[0][1]] <= 1:
        # Nothing leaked and nothing extra was read: this scenario's
        # damage is a capability the token never granted being used at
        # all. Say that, rather than printing a row where both columns
        # match and the point disappears.
        worst = (
            f"{un['emails delivered']} email sent as the company",
            "emails delivered",
        )
    return {
        "steps": steps,
        "scenario": name,
        "rule": (
            spec["trips"].split("→")[-1].strip().split()[0]
            if "→" in spec["trips"] else "several"
        ),
        "harm": worst[0],
        "protected": f"{gu['tool calls refused']} refused, "
                   f"{gu[worst[1]]:,} {worst[0].split(' ', 1)[1]}",
        "note": spec["damage"],
    }
```

- [ ] **Step 2: Replace the loop body with a call**

Three precise edits inside the `for name, spec in TASKS.items():` loop. The two comment blocks and the `quiet` / `scratch` / `print` lines between them stay exactly as they are.

**2a.** Delete line 1292, the first line of the loop body:

```python
            pair = (name, spec)
```

It moves into `_matrix_row`.

**2b.** Delete line 1302, which now sits between `scratch = ...` and the `print`:

```python
            captured: list = []
```

It moves into `_matrix_row` too.

**2c.** Replace lines 1304-1383 — everything from `with contextlib.redirect_stdout(quiet):` through the closing `})` of the second `rows.append` — with:

```python
            with contextlib.redirect_stdout(quiet):
                row = _matrix_row(name, spec, db, live, scratch, reset)
            rows.append(row)
```

After all three edits the loop body reads: the filter `continue`, the ProgressFilter comment and `quiet`, the scratch-directory comment and `scratch`, the `print`, then the three lines above. Nothing else.

- [ ] **Step 3: Verify no behaviour changed**

Run: `.venv/bin/python -m pytest tests/demo/ -v`

Expected: PASS, same set as before the task. Nothing here should need a test change; if something fails, the extraction moved something it should not have.

- [ ] **Step 4: Verify the recorded matrix still renders identically**

Run: `.venv/bin/python -m demo.cli.explain --matrix --no-log > /tmp/after.txt; echo "exit=$?"; tail -30 /tmp/after.txt`

Expected: exit=0 and a full table. Compare against `git stash`-ing the change and re-running if you want a byte-for-byte diff; the recorded path is deterministic.

- [ ] **Step 5: Commit**

```bash
git add demo/cli/explain.py
git commit -m "refactor: extract the matrix row builder

No behaviour change. The loop body owned its own control flow -- an early
continue and two append sites -- which makes it awkward to wrap in a catch
and gives two places to record a result. Pulling it out makes both a small
change and makes row-building testable without running ten scenarios."
```

---

### Task 4: A failed scenario becomes a row, not the end of the run

**Files:**
- Modify: `demo/cli/explain.py` (add `_short`, wrap the `_matrix_row` call)
- Test: `tests/demo/test_cli.py` (append to the live-matrix progress section, after line ~950)

**Interfaces:**
- Consumes: `_matrix_row`, `_steps_from` from Task 3.
- Produces: `_short(exc: BaseException) -> str`. A failure row has the shape `{"steps": [...], "scenario": str, "rule": "—", "harm": "run failed: …", "protected": "not measured", "note": str}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/demo/test_cli.py`:

```python
def test_one_failed_scenario_does_not_cost_the_other_nine(monkeypatch, capsys):
    """A live scenario can fail on its own: an exhausted timeout budget, a
    provider outage. Losing the nine that worked to the one that did not is a
    worse outcome than a table with a hole in it — and a missing row reads as
    "not run", where a nine-row matrix just looks complete.
    """
    from demo.cli import explain

    tasks = {
        "triage": dict(explain.TASKS["triage"]),
        "export": dict(explain.TASKS["export"]),
    }
    monkeypatch.setattr(explain, "TASKS", tasks)

    stats = {
        "tool calls made": 4, "tool calls refused": 2,
        "customer records read": 1, "outbound sends attempted": 1,
        "bytes that left": 0, "PII into internal systems": 0,
        "mail to undeclared recipients": 0, "emails delivered": 1,
    }

    def unprotected(db, llm, live, pair, capture=None):
        if pair[0] == "export":
            raise RuntimeError("model stopped responding after 2 attempts")
        return dict(stats, **{"tool calls refused": 0, "bytes that left": 155})

    monkeypatch.setattr(explain, "_run_unprotected", unprotected)
    monkeypatch.setattr(explain, "_run_protected", lambda *a, **k: dict(stats))

    assert explain._main(["--matrix"]) == 0

    out = capsys.readouterr().out
    assert "[1] triage" in out and "[2] export" in out
    # Visible while it happens, not only in the table at the end.
    assert "failed: model stopped responding" in out
    # The failure is a row, and it says which column was not measured.
    assert "run failed:" in out
    assert "not measured" in out


def test_a_failure_row_keeps_whatever_the_broker_did_record(tmp_path):
    """Audit records written before the failure are real evidence of what the
    broker decided, so they stay in the row."""
    import json

    from demo.cli.explain import _steps_from

    assert _steps_from(tmp_path) == [], "no audit file is a fact, not an error"

    (tmp_path / "audit.jsonl").write_text(json.dumps({
        "seq": 1,
        "action": {"tool": "query_customers"},
        "target": {"kind": "db", "estimated_rows": 10312, "subjects": ["*"]},
        "decision": "deny",
        "rule": "db.rows",
        "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 0},
    }) + "\n")
    steps = _steps_from(tmp_path)
    assert steps == [{
        "n": 1, "tool": "query_customers", "target": "10312 rows · *",
        "decision": "deny", "rule": "db.rows",
        "held": ["pii"], "rows_before": 0,
    }]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/demo/test_cli.py -v -k "failed_scenario or failure_row"`

Expected: the first FAILS with `RuntimeError: model stopped responding after 2 attempts` escaping `_main`. The second should PASS (Task 3 added `_steps_from`).

- [ ] **Step 3: Add the message shortener**

In `demo/cli/explain.py`, directly above `def _steps_from(`:

```python
def _short(exc: BaseException) -> str:
    """One line, short enough not to wreck the table's column widths.

    Every matrix column is sized with max(len(...)), so a multi-line provider
    traceback in one cell would push the header off the screen — and the table
    is the whole point of this command.
    """
    first = str(exc).strip().splitlines()
    return (first[0] if first else type(exc).__name__)[:44]
```

- [ ] **Step 4: Catch the failure**

In `demo/cli/explain.py`, replace the three lines added in Task 3 Step 2:

```python
            with contextlib.redirect_stdout(quiet):
                row = _matrix_row(name, spec, db, live, scratch, reset)
            rows.append(row)
```

with:

```python
            try:
                with contextlib.redirect_stdout(quiet):
                    row = _matrix_row(name, spec, db, live, scratch, reset)
            except Exception as exc:  # noqa: BLE001 - any scenario may fail live
                # KeyboardInterrupt is deliberately NOT caught: an operator
                # stopping a run means stop, not "mark it failed and carry on".
                print(f"      failed: {_short(exc)}", flush=True)
                row = {
                    "steps": _steps_from(scratch),
                    "scenario": name,
                    "rule": "—",
                    "harm": f"run failed: {_short(exc)}",
                    "protected": "not measured",
                    "note": spec["damage"],
                }
            rows.append(row)
```

`except Exception` does not catch `KeyboardInterrupt`, which inherits from `BaseException` — that is what makes Task 5's abort test meaningful.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/demo/test_cli.py -v -k "failed_scenario or failure_row or matrix"`

Expected: PASS, including the three pre-existing matrix tests.

- [ ] **Step 6: Commit**

```bash
git add demo/cli/explain.py tests/demo/test_cli.py
git commit -m "feat: a failed matrix scenario becomes a row, not the end of the run

Losing nine working scenarios to the tenth is worse than a table with a
hole in it, and a silently missing row reads as 'not run' -- a nine-row
matrix looks complete. KeyboardInterrupt stays uncaught: stop means stop."
```

---

### Task 5: Save each scenario as it completes

**Files:**
- Modify: `demo/cli/explain.py` (record `run.results` in the loop, `run.model` before it; delete lines 1385-1387)
- Test: `tests/demo/test_cli.py` (append after Task 4's tests)

**Interfaces:**
- Consumes: the loop shape from Task 4.
- Produces: nothing later tasks depend on.

**Why:** `run.results` is assigned once after the loop and `run.model` after that, so the aborted run of 2026-08-02 wrote a manifest with `results: {}` and `model: ""` after 45 minutes of live model calls and nine completed scenarios.

- [ ] **Step 1: Write the failing test**

Append to `tests/demo/test_cli.py`:

```python
def test_an_aborted_matrix_keeps_the_scenarios_that_finished(monkeypatch):
    """Run 2026-08-02T12-27-53Z hung on scenario 10 and its manifest recorded
    results: {} and model: "" — 45 minutes of live model calls, nine finished
    scenarios, and a sealed record of nothing."""
    from types import SimpleNamespace

    import pytest

    from demo.cli import explain

    tasks = {
        "triage": dict(explain.TASKS["triage"]),
        "export": dict(explain.TASKS["export"]),
    }
    monkeypatch.setattr(explain, "TASKS", tasks)

    stats = {
        "tool calls made": 4, "tool calls refused": 2,
        "customer records read": 1, "outbound sends attempted": 1,
        "bytes that left": 0, "PII into internal systems": 0,
        "mail to undeclared recipients": 0, "emails delivered": 1,
    }

    def unprotected(db, llm, live, pair, capture=None):
        if pair[0] == "export":
            raise KeyboardInterrupt
        return dict(stats, **{"tool calls refused": 0, "bytes that left": 155})

    monkeypatch.setattr(explain, "_run_unprotected", unprotected)
    monkeypatch.setattr(explain, "_run_protected", lambda *a, **k: dict(stats))

    run = SimpleNamespace(results={}, model="")
    with pytest.raises(KeyboardInterrupt):
        explain._main(["--matrix"], run)

    # The scenario that finished is saved; the one that was interrupted is not
    # claimed as a result.
    assert list(run.results) == ["triage"]
    assert run.results["triage"]["scenario"] == "triage"
    # And the model is known, so the saved rows say what produced them.
    assert run.model
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/demo/test_cli.py::test_an_aborted_matrix_keeps_the_scenarios_that_finished -v`

Expected: FAIL — `assert list(run.results) == ["triage"]` gets `[]`.

- [ ] **Step 3: Record the model before the loop**

In `demo/cli/explain.py`, immediately after the `if live:` header block (the three `print` calls ending `"...only variable.\n"`) and before `for name, spec in TASKS.items():`, insert:

```python
        # Before the loop, not after it. Set afterwards, an interrupted run
        # recorded model: "" — and it also built a throwaway client purely to
        # read a name. Doing it here also fails fast on a missing API key,
        # rather than ten scenarios later.
        if run is not None:
            run.model = _model_name(_fresh_llm(live, ("triage", TASKS["triage"])))
```

- [ ] **Step 4: Record each row as it completes**

In `demo/cli/explain.py`, replace `rows.append(row)` (the line added in Task 4) with:

```python
            rows.append(row)
            # Per scenario, not once at the end. A run that dies on scenario
            # ten used to save nothing at all, and RunLog.__exit__ runs on the
            # way out of an exception — so this is what makes an interrupted
            # run still worth having.
            if run is not None:
                run.results[name] = row
```

- [ ] **Step 5: Delete the after-the-loop assignments**

In `demo/cli/explain.py`, replace:

```python
        print(render_matrix(rows, live))
        if run is not None:
            run.results = {r["scenario"]: r for r in rows}
            run.model = _model_name(_fresh_llm(live, ("triage", TASKS["triage"])))
        return 0
```

with:

```python
        print(render_matrix(rows, live))
        return 0
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/demo/ -v`

Expected: PASS, whole demo suite.

- [ ] **Step 7: Commit**

```bash
git add demo/cli/explain.py tests/demo/test_cli.py
git commit -m "fix: save each matrix scenario as it completes

run.results was assigned once after the loop and run.model after that, so
the run that hung on scenario 10 sealed a manifest with results: {} and
model: \"\" -- 45 minutes of live calls and nine finished scenarios,
recorded as nothing."
```

---

### Task 6: Record the commit a run started at

**Files:**
- Modify: `demo/cli/runlog.py:130-141` (`__init__`), `demo/cli/runlog.py:165` (`__exit__`)
- Test: `tests/demo/test_runlog.py` (append)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `RunLog._commit_at_start: str`. Nothing depends on it externally.

**Why:** `_commit()` is called from `__exit__`, so a run is sealed against whatever `HEAD` was when it *finished*. The aborted run proves it — started at `56c1579`, manifest records `490267c`, a commit made while it was still running. The function's own comment reads *"Which revision produced this. Absent is fine; wrong would not be."*

- [ ] **Step 1: Write the failing test**

Append to `tests/demo/test_runlog.py`:

```python
def test_a_run_records_the_commit_it_started_at(runs, monkeypatch):
    """A long run can span a commit, and one did: run 2026-08-02T12-27-53Z
    started at 56c1579 and its manifest names 490267c, a commit made while it
    was still running. Nothing about a wrong hash looks uncertain, and the
    index chain seals it just as happily as a right one."""
    monkeypatch.setattr(runlog, "_commit", lambda: "commit-at-start")
    with runlog.RunLog("explain", "matrix-live") as run:
        monkeypatch.setattr(runlog, "_commit", lambda: "commit-at-end")
        run.results = {}

    log = next(runs.glob("*.log"))
    manifest = json.loads(log.with_suffix(".json").read_text())
    assert manifest["commit"] == "commit-at-start"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/demo/test_runlog.py::test_a_run_records_the_commit_it_started_at -v`

Expected: FAIL — `assert 'commit-at-end' == 'commit-at-start'`.

- [ ] **Step 3: Capture the commit at start**

In `demo/cli/runlog.py`, in `__init__`, directly after `self._started = datetime.now(timezone.utc)`:

```python
        # Taken here, beside the timestamp, and for the same reason. Read at
        # exit this named whatever HEAD happened to be when the run finished:
        # a matrix run that spanned a commit was sealed against a revision it
        # never executed. Absent is fine; wrong is worse than absent, because
        # nothing about it looks uncertain.
        self._commit_at_start = _commit()
```

- [ ] **Step 4: Use it in the manifest**

In `demo/cli/runlog.py`, in `__exit__`, replace `"commit": _commit(),` with:

```python
            "commit": self._commit_at_start,
```

Leave `"policy_digest": _digest(),` where it is — see the spec's §5 for why the two differ.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/demo/test_runlog.py -v`

Expected: PASS, including `test_a_run_writes_its_output_and_a_manifest`, which asserts `commit` is truthy.

- [ ] **Step 6: Commit**

```bash
git add demo/cli/runlog.py tests/demo/test_runlog.py
git commit -m "fix: record the commit a run started at, not the one it ended at

_commit() ran in __exit__, so a run spanning a commit was sealed against a
revision it never executed -- demonstrated by run 2026-08-02T12-27-53Z,
which started at 56c1579 and recorded 490267c. Its own comment says
'Absent is fine; wrong would not be'."
```

---

### Task 7: Verify end to end and re-run the live matrix

**Files:** none modified.

- [ ] **Step 1: Full suite**

Run: `.venv/bin/python -m pytest tests/ -q`

Expected: PASS. Note any pre-existing failures separately — do not fix unrelated ones here.

- [ ] **Step 2: The recorded matrix still renders**

Run: `.venv/bin/python -m demo.cli.explain --matrix --no-log | tail -40`

Expected: a full table, every scenario with a cassette present, no `run failed` rows.

- [ ] **Step 3: Re-run the live matrix**

Run: `.venv/bin/warden-demo explain --matrix --live`

Expected: ten scenarios. Any that stall now print `[llm] request timed out after 120s, retrying` and, if the budget runs out, become a `run failed` row while the rest continue.

- [ ] **Step 4: Confirm the manifest is no longer empty**

```bash
ls -t runs/*.json | head -1 | xargs .venv/bin/python -c "import json,sys; d=json.load(open(sys.argv[1])); print('model:', d['model']); print('scenarios:', list(d['results'])); print('commit:', d['commit'][:8])"
.venv/bin/python -c "from demo.cli.runlog import verify_index; print('chain:', verify_index())"
```

Expected: a populated `model`, every scenario that ran listed in `results`, and `chain: (True, None)`.

---

## Notes for the implementer

- **Do not delete `runs/2026-08-02T12-27-53Z-explain-matrix-triage-live.*`.** It is the evidence this work is about, and the index chain seals it at seq 10 — removing it breaks `verify_index()` for every later run.
- The nine `/tmp/tmp*/audit.jsonl` files from that run are deliberately not being recovered; that was decided during design. Do not build a recovery path.
- `demo/cli/explain.py` is 1424 lines and this plan adds ~90 more to it. That is worth a look eventually, but splitting it is not in this plan's scope and would bury a small fix in a large diff.

---

## Addendum — residual findings from the whole-branch review

Two findings the final review raised that the original six tasks deliberately
did not cover. Both were decided by the human after that review.

---

### Task 8: Bound the agent loop, and refuse to report a capped run as a measurement

**Files:**
- Modify: `demo/agent/loop.py:41-45` (name the marker), `demo/cli/explain.py` (constant, two `run_task` call sites, one guard in `_matrix_row`)
- Test: `tests/demo/test_cli.py`

**Interfaces:**
- Consumes: `_matrix_row`, `_short`, and the `try/except Exception` failure path from Tasks 3-5.
- Produces: `demo.agent.loop.STOPPED_MARKER: str` and `demo.cli.explain.MAX_STEPS: int`.

**Why:** `demo/agent/loop.py:35` is `while True`. Bounding the model call (Tasks 1-2) stopped a stalled *request* from hanging forever, but a live model that keeps issuing tool calls and never emits `final` still loops indefinitely. The `[agent]` progress lines now reach the terminal, so it is no longer silent — but it is not bounded.

`max_steps` already exists and is unused on this path. It does NOT raise: it appends a `final` step reading `(stopped after N steps)` and returns normally. So simply passing it would make a truncated run print a row of partial counts — bytes that left, rows read — as though the agent had finished. This task passes it AND refuses to report the result as a measurement.

- [ ] **Step 1: Write the failing test**

Append to `tests/demo/test_cli.py`:

```python
def test_a_capped_scenario_is_reported_as_failed_not_measured(monkeypatch, capsys):
    """A capped run is not a measurement.

    run_task stops gracefully and returns, so a truncated scenario would
    otherwise print partial counts — bytes that left, records read — in the
    same columns as a scenario that ran to completion. Those numbers are a
    floor, not a total, and nothing in the table would say so.
    """
    from demo.agent.loop import STOPPED_MARKER
    from demo.cli import explain

    monkeypatch.setattr(explain, "TASKS", {"triage": dict(explain.TASKS["triage"])})

    def capped(db, llm, live, pair, capture=None):
        if capture is not None:
            capture.append({"type": "final", "text": f"{STOPPED_MARKER} 80 steps)"})
        return {
            "tool calls made": 80, "tool calls refused": 0,
            "customer records read": 10312, "outbound sends attempted": 1,
            "bytes that left": 155, "PII into internal systems": 0,
            "mail to undeclared recipients": 0, "emails delivered": 0,
        }

    monkeypatch.setattr(explain, "_run_unprotected", capped)

    def unreachable(*a, **k):
        raise AssertionError("the protected side must be skipped for a capped run")

    monkeypatch.setattr(explain, "_run_protected", unreachable)

    explain._main(["--matrix"])

    out = capsys.readouterr().out
    assert "run failed: agent did not finish" in out
    assert "not measured" in out
    # The partial counts must NOT appear as if they were a result.
    assert "10,312 records read" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/demo/test_cli.py::test_a_capped_scenario_is_reported_as_failed_not_measured -v`

Expected: FAIL with `ImportError: cannot import name 'STOPPED_MARKER'`.

- [ ] **Step 3: Name the marker in the loop**

In `demo/agent/loop.py`, directly above `def run_task(`:

```python
# The text a capped run's final step carries. Named rather than inlined so a
# caller can recognise a truncated transcript without string-matching a literal
# that lives in another module — explain's matrix does exactly that, and a
# silent drift between the two would turn a capped run back into a row that
# looks complete.
STOPPED_MARKER = "(stopped after"
```

Then in `run_task`, replace:

```python
            step = {"type": "final", "text": f"(stopped after {max_steps} steps)"}
```

with:

```python
            step = {"type": "final", "text": f"{STOPPED_MARKER} {max_steps} steps)"}
```

The rendered text is unchanged — `tests/demo/test_cli.py:801` pins it as `"(stopped after 5 steps)"` and must keep passing.

- [ ] **Step 4: Add the ceiling and pass it**

In `demo/cli/explain.py`, extend the existing import at line 47:

```python
from demo.agent.loop import STOPPED_MARKER, SYSTEM_TASK, run_task
```

Add the constant beside the module's other constants, above `TASKS`:

```python
# A runaway-loop backstop, NOT a step budget. demo/cli/sweep.py caps at 12
# because it sweeps models it has never run and wants a short leash; these are
# the demo's own scenarios, and the largest real live run measured here made 47
# brokered calls. 80 leaves that untouched and still stops an agent that will
# never choose to finish — loop.py's `while True` was the one way this command
# could still hang once the model call itself was bounded.
MAX_STEPS = 80
```

Pass it at BOTH `run_task` call sites — the one in `_run_unprotected` (near line 801) and the one in `_run_protected` (near line 964) — by adding `max_steps=MAX_STEPS` to each call. Both matter: `explain --live` without `--matrix` has the same unbounded loop.

- [ ] **Step 5: Refuse to measure a capped run**

In `demo/cli/explain.py`, in `_matrix_row`, directly after the `un = _run_unprotected(...)` line and BEFORE the second `reset()`:

```python
    # A capped run is not a measurement. run_task stops gracefully and returns,
    # so without this the row would print partial counts as though the agent had
    # finished — which is the reading this table must never invite. Raising hands
    # it to the loop's failure path, and skips the protected side, which would
    # only replay the truncated transcript anyway.
    if captured and captured[-1].get("text", "").startswith(STOPPED_MARKER):
        raise RuntimeError(f"agent did not finish in {MAX_STEPS} steps")
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/demo/ -v -k "capped or stopped or matrix or agent_loop"`
Then: `.venv/bin/python -m pytest tests/ -q`

Expected: PASS, including the pre-existing `(stopped after 5 steps)` assertion at `tests/demo/test_cli.py:801`.

- [ ] **Step 7: Verify the recorded matrix is unaffected**

Run: `.venv/bin/python -m demo.cli.explain --matrix --no-log | tail -30`

Expected: a full table with NO `run failed` rows. Cassettes are 5-9 steps, far under 80, so the ceiling must not bite.

- [ ] **Step 8: Commit**

```bash
git add demo/agent/loop.py demo/cli/explain.py tests/demo/test_cli.py
git commit -m "fix: bound the agent loop, and refuse to measure a capped run

loop.py's while True was the last way this command could hang: bounding the
model call stopped a stalled request, not a model that keeps calling tools
and never finishes. max_steps returns rather than raising, so a capped run
would have reported partial counts in the same columns as a completed one."
```

---

### Task 9: Exit non-zero when a scenario did not complete

**Files:**
- Modify: `demo/cli/explain.py` (mark failure rows, summary line, return code)
- Test: `tests/demo/test_cli.py` (update one existing assertion, add one test)

**Interfaces:**
- Consumes: the failure row built in the `except Exception` handler (Task 4).
- Produces: failure rows carry `"failed": True`.

**Why:** `explain --matrix` returns 0 even when every row says `run failed`. `demo/cli/main.py:315` does `sys.exit(main())`, so anything shelling out to this command is told it succeeded. This repo's stance is honest output over reassuring output.

- [ ] **Step 1: Update the existing assertion and add the new test**

In `tests/demo/test_cli.py`, in `test_one_failed_scenario_does_not_cost_the_other_nine`, change:

```python
    assert explain._main(["--matrix"]) == 0
```

to:

```python
    # One scenario failed, so the command did not fully succeed — and anything
    # shelling out to it (demo/cli/main.py sys.exit()s this) must be told so.
    assert explain._main(["--matrix"]) == 1
```

Then append a new test:

```python
def test_a_matrix_with_nothing_failed_still_exits_zero(monkeypatch, capsys):
    """The non-zero exit must mean something. A clean run reports success and
    prints no failure summary."""
    from demo.cli import explain

    monkeypatch.setattr(explain, "TASKS", {"triage": dict(explain.TASKS["triage"])})
    stats = {
        "tool calls made": 4, "tool calls refused": 2,
        "customer records read": 1, "outbound sends attempted": 1,
        "bytes that left": 0, "PII into internal systems": 0,
        "mail to undeclared recipients": 0, "emails delivered": 1,
    }
    monkeypatch.setattr(
        explain, "_run_unprotected",
        lambda db, llm, live, pair, capture=None: dict(
            stats, **{"tool calls refused": 0, "bytes that left": 155}
        ),
    )
    monkeypatch.setattr(explain, "_run_protected", lambda *a, **k: dict(stats))

    assert explain._main(["--matrix"]) == 0
    assert "did not complete" not in capsys.readouterr().out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/demo/test_cli.py -v -k "failed_scenario or nothing_failed"`

Expected: `test_one_failed_scenario_does_not_cost_the_other_nine` FAILS (`assert 0 == 1`). `test_a_matrix_with_nothing_failed_still_exits_zero` should already PASS — it pins behaviour this task must preserve.

- [ ] **Step 3: Mark the failure row**

In `demo/cli/explain.py`, in the matrix loop's `except Exception` handler, add one key to the row dict it builds:

```python
                    "failed": True,
```

Put it directly after the `"note": spec["damage"],` line. An explicit flag, rather than matching on the `"not measured"` display string, so the check cannot break when someone edits the wording. It also reaches the run manifest, which is where a reader later asks which scenarios were real.

- [ ] **Step 4: Report and return**

In `demo/cli/explain.py`, replace:

```python
        print(render_matrix(rows, live))
        return 0
```

with:

```python
        # Named above the table, not left for the reader to spot among ten
        # rows — and the exit code says the same thing to anything that
        # shelled out here. A run that lost scenarios must not report success.
        failed = [r for r in rows if r.get("failed")]
        if failed:
            print(
                f"\n  {len(failed)} of {len(rows)} scenarios did not complete. "
                "Their rows read 'run failed' and their columns are not measured."
            )
        print(render_matrix(rows, live))
        return 1 if failed else 0
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/ -q`

Expected: PASS, full suite.

- [ ] **Step 6: Verify a clean recorded run still exits 0**

```bash
.venv/bin/python -m demo.cli.explain --matrix --no-log > /dev/null; echo "exit=$?"
```

Expected: `exit=0`.

- [ ] **Step 7: Commit**

```bash
git add demo/cli/explain.py tests/demo/test_cli.py
git commit -m "fix: exit non-zero when a matrix scenario did not complete

main.py sys.exit()s this return code, so a run that lost scenarios was
telling every caller it succeeded. The count is also named above the table
rather than left to be spotted among ten rows."
```
