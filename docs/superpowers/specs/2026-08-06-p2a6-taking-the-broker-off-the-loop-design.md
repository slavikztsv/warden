# P2·A6 — taking the enforcement point off the event loop

**Status:** approved design, not yet implemented
**Sequenced by:** [docs/ROADMAP.md](../../ROADMAP.md) § A (Phase 2), item A6 —
and § B item B1, pulled forward for the reason argued in decision 1.
**Covers:** B1 (constant-time audit append) and A6 (the spine off the loop).
**Deliberately does not cover:** A2 (the Redis store) and B6 (multi-writer
sequencing). See *What this does not do*.
**Verified against:** a full read of `warden/broker/spine.py`,
`warden/broker/app.py`, `warden/broker/mcp.py`, `warden/broker/proxy.py`,
`warden/broker/audit.py`, `warden/broker/pdp.py`, all four adapters,
`demo/cli/explain.py`'s wrappers, `.github/workflows/ci.yml`, and four
measurements recorded below.

---

## What this is

The broker serves **one tool call at a time, per process**, and the egress
proxy shares that event loop. A ten-second SQL read stalls every `CONNECT`
behind it, including tunnel setup for calls that have nothing to do with it.
[`ROADMAP.md:78`](../../ROADMAP.md) calls this "a correctness win by accident
and a throughput ceiling by construction".

The correctness half is gone: P2·A replaced it with the store's atomic charge,
and [`spine.py:16-20`](../../../warden/broker/spine.py) says so — *"The
synchrony here is a fact about today's implementation, not a control, and A6
may remove it without removing anything that protects the budget."* What is
left is the ceiling. This document removes it.

Five decisions were taken before any of this was written. Each is stated with
the alternative it beat, because a decision recorded without its loser is
indistinguishable from an accident.

---

## Where the line is today

**Every collaborator the spine calls blocks.** The PDP uses a blocking
`httpx.Client` inside an `async def` handler
([`pdp.py:47`](../../../warden/broker/pdp.py)); `AuditLog.append` does
synchronous file IO under a `threading.Lock`
([`audit.py:85-112`](../../../warden/broker/audit.py)); every adapter's
`describe()` and `execute()` is a plain `def`. The event loop cannot reach
another request during any of it.

**There are five call sites, and no interface between them is async.**
`spine.authenticate` and `spine.handle_tool_call`
([`app.py:239`](../../../warden/broker/app.py),
[`app.py:247`](../../../warden/broker/app.py)), `spine.list_tools` and
`spine.handle_tool_call` again ([`mcp.py`](../../../warden/broker/mcp.py)'s
`on_list_tools` / `on_call_tool`, the latter at
[`mcp.py:509`](../../../warden/broker/mcp.py)), and `authorize_connect`
([`proxy.py:267`](../../../warden/broker/proxy.py)).

**The audit append is O(n) per call, so the log is O(n²).** `_head()` calls
`records()`, which reads and JSON-parses the *entire* file, on every append
([`audit.py:64-69`](../../../warden/broker/audit.py)) — and it does so
**inside** the lock ([`audit.py:85-86`](../../../warden/broker/audit.py)).
Measured on this machine:

| records already in the log | one `append()` |
|---|---|
| 100 | 0.76 ms |
| 500 | 4.66 ms |
| 1 000 | 8.01 ms |
| 2 000 | 18.28 ms |
| 4 000 | 37.08 ms |

4 000 appends took **71.8 s** in total, for a 2.3 MB file.

**A corrupt log fails at first use, not at boot, and not as an `OSError`.**
`records()` raises `json.JSONDecodeError` on a malformed line. That is not an
`OSError`, so neither `_deny`'s guard
([`spine.py:570`](../../../warden/broker/spine.py)) nor `handle_tool_call`'s
([`spine.py:346`](../../../warden/broker/spine.py)) catches it; it escapes as
an unhandled 500.

---

## The five decisions

### 1 · B1 lands first, because without it A6 delivers nothing

Offloading the spine to a threadpool moves every concurrent caller onto
`AuditLog._lock`. That lock is held across a full file parse whose cost grows
without bound, so the throughput ceiling A6 exists to remove would simply
reappear a few thousand records later — and be *harder* to see, because it
would look like contention rather than like serialisation.

The table above is the argument. At 4 000 records the broker cannot exceed
~27 audited decisions per second no matter how many threads serve it, and that
number falls every time it serves one.

So B1 is in scope, and it lands **as its own commit, before** the offload, so
the two diffs are separately reviewable.

*Rejected:* A6 alone, with B1 following. It ships a change whose stated benefit
is not measurable, and the repository's convention is that a claim ships with
the run that produced it. *Also rejected:* pulling in B2 (`fsync`) and B3
(rotation) while in the file. Neither is on the path of this bottleneck, and B2
in particular trades durability against exactly the latency this document is
trying to reduce — it deserves its own argument, not a ride-along.

### 2 · The chain head is cached, and read once at construction

`AuditLog.__init__` reads the log once and keeps `(seq, prev_hash)`. `append()`
computes from the cached pair and advances it **after** the write returns.
`records()` and `verify_chain()` are untouched: they still read the file, which
is what makes them an independent check on the thing that wrote it rather than
a restatement of it.

**Advancing after the write, never before, is the load-bearing detail.** If the
write raises, the cache still describes what is actually on disk, so the next
append computes from the true head. Advancing first would leave the cache one
record ahead of the file and silently break the chain at the *next* successful
append — a corruption whose cause is one call removed from its symptom.

The single-writer assumption is unchanged. It is the assumption
[`audit.py:47-52`](../../../warden/broker/audit.py) already encodes in a
`threading.Lock`, and B6 is what lifts it. Caching adds no new one.

**Reading at construction rather than lazily is deliberate**, and it changes a
failure mode for the better: a corrupt log now refuses to boot instead of
escaping as a 500 at first use. That follows
[`loader.py:7-10`](../../../warden/broker/config/loader.py) — *"A broker that
starts with a half-understood config writes audit records claiming a policy it
is not enforcing, and that is worse than not starting."* An audit log it cannot
parse is the same case.

*Rejected:* seeking to the last line instead of caching. It is O(1) too, but it
keeps a file read on the serving path, so it stays vulnerable to the same
class of surprise, and it reads bytes whose meaning the process already knows.

### 3 · The spine is offloaded at its call sites, not converted to async

Each of the five call sites becomes `await loop.run_in_executor(executor, ...)`.
`Spine.handle_tool_call` stays a plain `def`. `PolicyDecisionPoint.decide`
stays sync. Every adapter stays sync. `TaskStateStore` stays sync.
`authorize_connect` stays a plain function.

**Zero interfaces change, and that is the whole argument.** The alternative —
`ROADMAP.md:222`'s literal wording, `httpx.AsyncClient` in the PDP plus
adapters on a threadpool plus an awaitable `authorize_connect` — converts a
five-method Protocol, three test doubles, the adapter base class the README
advertises as the extension point, and four wrappers in
[`demo/cli/explain.py`](../../../demo/cli/explain.py) that `mypy` does not
check (CI checks `warden/` alone,
[`ci.yml:52-57`](../../../.github/workflows/ci.yml)). Those wrappers forward
hand-written subsets of interfaces and rot **silently**: commit `794d876` is
that exact bug, where a missing `ToolCatalog.data_class` turned every brokered
call in the demo into a tidy 502 with no audit record while 753 tests stayed
green.

Two further facts make the conversion route worse than it looks:

- **A missed `await` is not caught where it matters.** `mypy` flags a
  discarded or value-used coroutine, but `Spine._settle`
  ([`spine.py:533`](../../../warden/broker/spine.py)) takes its `operation`
  parameter unannotated, so a coroutine passed through it is `Any` — and
  [`spine.py:544`](../../../warden/broker/spine.py)'s `except Exception: pass`
  swallows the result. `ruff.toml` selects no type-aware rule, and `pytest.ini`
  sets no `filterwarnings`, so `RuntimeWarning: coroutine was never awaited` is
  not an error either.
- **A half-converted PDP fails closed but silently.**
  [`pdp.py:52`](../../../warden/broker/pdp.py) catches `TypeError`, so awaiting
  a `httpx.Client` response returns `Decision(allow=False, rule=UNAVAILABLE)` —
  every call denied, each one written into the tamper-evident chain as a policy
  denial, with the broker reporting healthy.

The offload route has neither failure mode: there is no client flavour to
mismatch, no `await` to forget, and no wrapper to convert.

**This is the model `audit.py` was already written for.**
[`audit.py:47-52`](../../../warden/broker/audit.py) explains its lock as
guarding *"two concurrent callers (e.g. FastAPI sync handlers running in
Starlette's threadpool)"*. And § A's exit-criterion test
(`test_app.py`'s ten-thread reader) already drives `spine.handle_tool_call`
from ten real OS threads, with its docstring stating the reason: *"the spine's
synchronous entry point IS what a threadpooled or multi-worker deployment
calls concurrently"*. Offload makes that test a faithful model of production
rather than a stand-in for one, so §A's criterion test needs no rewrite — and
a criterion test rewritten is where criteria get quietly weakened.

**`httpx.Client` sharing across threads was measured, not assumed.** At the
pinned `httpx==0.28.1`, 32 threads against a real socket server produced **zero
cross-thread response mixing**. A ~1% `ReadError` rate appeared, and the
discriminating run shows it is not httpx: per-thread clients with no sharing at
all produced the same rate (10 errors vs 7), and a single thread doing the same
volume produced none. It is the test server under 32 connections. `sqlite3` is
safe by construction — [`sql.py:140/147`](../../../warden/broker/adapters/sql.py)
and [`sql.py:158/165`](../../../warden/broker/adapters/sql.py) each open *and*
close a connection inside one method, so no connection crosses a thread. There
are zero uses of `contextvars` or `threading.local` anywhere in `warden/`.

*Rejected:* `ROADMAP.md:222`'s literal three-part conversion, for the reasons
above. The **property** it names — the PDP and the adapters off the loop — is
delivered; the mechanism is one instead of three. That is a roadmap wording
edit, made explicitly, not a scope cut.

### 4 · The broker owns its executor, and its size is configuration

`asyncio.to_thread` uses the event loop's *default* executor, whose size is
`min(32, os.cpu_count() + 4)` — 12 on this machine. That number is invisible,
machine-dependent, undocumented, and shared with anything else in the process
that calls `to_thread`.

For a product whose whole pitch is stating its own limits, an invisible
machine-dependent concurrency bound is the wrong default. The broker
constructs its own `ThreadPoolExecutor`, sized by a new optional
`[broker] worker_threads` key (default **16**), and every offloaded call site
uses it.

```toml
[broker]
worker_threads = 16
```

`_positive` already exists in the loader for exactly this shape, and rejects
zero — a zero-thread executor would deadlock every request, which is precisely
the class of quiet weakening that loader turns into a boot failure.

**One executor, shared by the tool API and the proxy, and the trade is stated
rather than hidden.** They already share one event loop
([`__main__.py:161-166`](../../../warden/broker/__main__.py)), so a burst of
slow tool calls can delay `CONNECT` authorization. That is strictly better than
today, where a single slow read blocks every `CONNECT` completely, and it fails
in the safe direction: a queued `CONNECT` waits, it is never wrongly allowed.

**Queue time cannot expire a reservation.** A request waiting for a thread has
not charged anything yet — `now` is read *inside* `handle_tool_call`
([`spine.py:225`](../../../warden/broker/spine.py)), and the reservation
deadline is `now + max_in_flight_seconds` computed from it. So executor
saturation delays calls; it cannot cause a live call's budget to be collected
and handed to a concurrent caller.

*Rejected:* separate executors for the API and the proxy. It removes the
starvation coupling, but at the price of two knobs, two saturation modes to
reason about, and a second number in `DEPLOYMENT.md` — for a coupling that
fails closed. If egress starvation is ever observed, that is the fix, and it is
a one-line change to a call site that already names its executor.

### 5 · The test that asserts the old property is inverted, not deleted

`tests/warden/test_mcp_surface.py`'s
`test_the_spine_runs_on_the_event_loop_not_a_worker_thread` asserts
`threads == [loop_thread]`. Its stated premise is *"the taint snapshot and the
read it authorises happen on one thread with no scheduling boundary between
them"* — and that premise is **already disowned** by
[`spine.py:16-20`](../../../warden/broker/spine.py) and
[`taint.py:98-103`](../../../warden/broker/taint.py). There is no taint
snapshot any more; there is a charge.

Deleting a test that names a security property is how properties get lost, so
it is inverted rather than removed: it asserts the spine runs **off** the loop
thread, and its docstring records what replaced the property it used to guard —
the store's atomic charge, pinned by the ten-thread test.

And because the MCP surface is now a second front door onto a threadpooled
spine, the exit-criterion property is driven through it too, not only through
the tool API. A property proven on one surface and assumed on the other is the
drift `test_surface_parity.py` exists to prevent.

*Rejected:* keeping the test and exempting the MCP path from the offload. It
would preserve a green assertion by making one front door slower than the
other, which is the two-surfaces-that-disagree failure the shared spine exists
to make impossible.

---

## What changes where

| File | Change |
|---|---|
| `warden/broker/audit.py` | `_head` cached at construction, advanced after a successful write. `records()`/`verify_chain()` untouched |
| `warden/broker/app.py` | Owns the executor; `authenticate` and `handle_tool_call` awaited through it |
| `warden/broker/mcp.py` | `on_list_tools` and `on_call_tool` awaited through the same executor; the docstring's claim about the SDK threadpooling sync handlers is corrected — `runner.py:217` awaits handlers unconditionally |
| `warden/broker/proxy.py` | `authorize_connect` awaited through the executor |
| `warden/broker/config/loader.py` | `[broker] worker_threads`, optional, default 16, `_positive` |
| `warden/broker/wiring.py`, `__main__.py` | Construct the executor, thread it to both surfaces, shut it down with the server |
| `tests/warden/test_audit.py` | Constant-time append; the cache is not advanced by a failed write; a corrupt log refuses at construction |
| `tests/warden/test_mcp_surface.py` | The thread assertion inverted (decision 5) |
| `tests/warden/test_app.py`, `test_proxy.py` | The offload is observable; the exit criterion still holds through both surfaces |
| `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/DEPLOYMENT.md`, `docs/ROADMAP.md` | The ceiling is gone; the one-worker requirement is **not**, and its stated reason is corrected |

**`DEPLOYMENT.md:27-28` is already false and is fixed on the way past.** It says
*"The row budget has no lock and relies on a single event loop."* P2·A gave it a
lock ([`taint.py:114`](../../../warden/broker/taint.py)). The **requirement**
stands — one worker, because two brokers share no store — but the reason given
for it has been wrong since `aa02c8a`.

---

## How each property is proven

The suite being green has repeatedly not been evidence in this repository, so
each property names the mutation that must break it. A test that does not fail
when its guard is removed is not a test.

| Property | Test | Mutation that must turn it red |
|---|---|---|
| The append does not re-read the log | Spy on `records()`; N appends after construction must call it **zero** times | Restore `_head()` to calling `records()` |
| A failed write does not advance the cache | Make the write raise; assert the next append still links to the true head | Advance the cache before the write instead of after |
| A corrupt log refuses at boot | Construct over a malformed line; assert it raises there, not at first append | Read the head lazily |
| The chain still verifies under concurrency | The existing 25-thread append test | — (this one must *not* move) |
| The spine runs off the loop thread | Both surfaces: assert the spine's thread is not the loop's | Call the spine directly instead of through the executor |
| The executor is the broker's own, not the default | Assert the offloaded call runs on a thread from the configured pool | Use `asyncio.to_thread` |
| `worker_threads = 0` refuses to boot | Loader test | Drop `_positive`'s zero rejection |
| The budget is still honoured exactly once | The existing ten-thread test, **plus** the same property through the MCP surface | Replace the charge with a plain read |
| Sequential runs are unchanged | The golden decision corpus, the replay pair, and `warden-demo explain` | — (this one must *not* move) |

`opa test`, the decision corpus and the replay pair keep their existing roles.
No policy input changes, so `tests/golden/audit-4711.jsonl` is **not**
regenerated — the frozen chain stays frozen.

---

## What this does not do

- **A2, the Redis store.** Two brokers still share no budget. Single-worker
  deployment remains a requirement, and the README's limitation is not deleted.
  A2 gets cheaper because of this work, not harder: with the spine already on a
  threadpool, a synchronous Redis client is the right client, and the
  sync-versus-async question that would otherwise dominate its design does not
  arise.
- **B6, multi-writer sequencing.** `seq` is still allocated under a
  process-local lock. B1 makes that allocation fast; it does not make it
  shared.
- **§ A's exit criterion.** Four workers behind a load balancer needs A2 **and**
  B6 **and** a process model that does not exist today — there is no `healthz`,
  no `readyz`, no `SO_REUSEPORT`, and `__main__.py` binds the proxy inside the
  same `asyncio.run` as uvicorn. This document moves none of that.
- **❌ Production.** It does not move. Phase 3 is still the gate.
- **B2 (`fsync`) and B3 (rotation).** Named here only because this touches
  `audit.py` and a reader will wonder. B2 trades durability against the exact
  latency B1 just recovered, and deserves its own argument.
