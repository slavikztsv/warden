# P2·A — shared, durable task state: the store and what its number means

**Status:** approved design, not yet implemented
**Sequenced by:** [docs/ROADMAP.md](../../ROADMAP.md) § A (Phase 2).
**Covers:** A1 (extract the store), A3 (reserve-then-reconcile), A4 (release on
failure), A5 (TTL eviction).
**Deliberately does not cover:** A2 (the Redis implementation) and A6 (the
async spine). Each gets its own spec; see *What this does not do*.
**Verified against:** a full read of `warden/broker/taint.py`,
`warden/broker/spine.py`, `warden/policies/authz.rego`, all four adapters, and
`tests/golden/README.md`.

---

## What this is

The roadmap calls § A "the load-bearing one. Everything in the 'production'
definition depends on it." This document settles the part of § A that can be
*wrong* — what a task's budget number means, and what the interface for
changing it is — and proves it against the in-memory implementation. The Redis
store is then an implementation of a contract that has already been argued and
tested, rather than a redesign wearing a Lua script.

Six decisions were taken before any of this was written. Each is stated below
with the alternative it beat, because a decision recorded without its loser is
indistinguishable from an accident.

---

## Where the line is today

**The estimate is already judged; it is simply not held.** R5 in
[`authz.rego:348-352`](../../../warden/policies/authz.rego) denies when
`rows_returned_so_far + estimated_rows > max_rows_per_task`. The decision
already prices the call. What is missing is that nothing reserves that price
between the decision and [`spine.py:290`](../../../warden/broker/spine.py)'s
`record_read`, so N calls that snapshot before any of them records all see the
same starting budget and all pass.

**Today that hole is closed by an accident.** `Spine.handle_tool_call` contains
no `await`, and every collaborator it calls is blocking, so the broker serves
one tool call at a time per process. The spine's own module docstring says as
much and calls it a security property. It is — but it is a property of the
call graph, not of the state, and A6 and multi-worker each dissolve it.

**`data_classes_held` has the same hole, and § A does not mention it.**
[`spine.py:196`](../../../warden/broker/spine.py) snapshots the class set and
only [`spine.py:290`](../../../warden/broker/spine.py) adds to it, after
`execute()` returns. A PII read in flight while a concurrent HTTP send
snapshots "no classes held" walks straight past R4 `egress.pii_sink` — the
data-flow control the README's headline scenario turns on. That is a worse
outcome than an overspent row budget, and it is the same defect.

**Nothing is ever evicted.** `TaintTracker._tasks` is a `defaultdict` that only
grows.

---

## The six decisions

### 1 · The budget is charged, not counted

**`rows_charged_so_far` = rows this task has committed to reading: settled
reads plus reservations in flight.** A call is priced at `describe()`'s
estimate, charged before it runs, and its reservation is swapped for the true
count when it returns.

This is stricter than counting what came back, and the strictness *is* the
control. Two concurrent 50-row reads against a 50-row budget:

| | charge returns (pre-state) | R5 evaluates | outcome |
|---|---|---|---|
| A | 0 | `0 + 50 = 50`, not `> 50` | allow |
| B | 50 | `50 + 50 = 100 > 50` | deny `rows.bounded`, release |

Exactly one allow, decided by the atomic charge's ordering — for N callers, the
longest prefix that fits, and no more. Under sequential calls (every demo run,
every golden decision, the `report` scenario) each call reconciles before the
next charges, so the arithmetic is identical to today's.

*Rejected:* charging the estimate and never giving it back — simpler, no A4,
but a `describe()` that counts 50 and an `execute()` that returns 3 would spend
50 of 50 forever. *Also rejected:* keeping today's semantics and serialising a
task's calls under a per-task lock — it preserves the number's meaning exactly,
but holds a lock across a network call (so a distributed lease needs fencing,
and lease expiry mid-`execute()` is a correctness hole) and reduces
intra-task parallelism to zero, which is precisely what agents doing parallel
tool calls need.

**Overshoot is permitted and recorded.** If `execute()` returns more rows than
`describe()` counted — SQL opens two separate connections
([`sql.py:140`](../../../warden/broker/adapters/sql.py),
[`sql.py:159`](../../../warden/broker/adapters/sql.py)), so a table growing
between them is the ordinary cause — reconcile commits the actual count, the
task may end up over budget, and the *next* call is denied. Capping at
`execute()` would silently truncate a result, which
[`base.py`](../../../warden/broker/adapters/base.py) already refuses to do for
the count itself.

### 2 · The store increments; OPA still judges

The limit lives in `data.limits.max_rows_per_task`
([`authz.rego:310-315`](../../../warden/policies/authz.rego)) — OPA's data, not
the broker's. So `charge` is an **unconditional** atomic increment that returns
the state *before* it. The broker passes that pre-state as the policy input,
and R5 applies today's arithmetic to today's field.

**The rego does not change** beyond the field rename in decision 5. The limit
stays in exactly one place, `rows.bounded` stays a decision OPA made, and the
audit record's rule keeps coming from the decision function.

*Rejected:* A2's literal wording, a Lua script that checks the limit itself.
It would put the budget in OPA data *and* in Redis config — the same drift
class D5 names for the policy digest — and would make the broker synthesise a
`rows.bounded` denial from a store result. *Also rejected:* having OPA return
the remaining headroom for a conditional increment to check; the policy would
have to expose headroom (so a custom policy that does not breaks), and the
denial is still synthesised rather than decided.

The cost, stated: a call denied for an unrelated rule — `tools.allowed`,
`rows.scope` — still took a reservation and released it. That is one extra
store round trip on the deny path, and a transient reservation visible to a
concurrent call for the duration of one PDP call.

### 3 · Both halves of task state are charged

One `charge` covers the row reservation **and** the tool binding's declared
data class. The class is knowable before `execute()`: it is a static binding
property on all four adapter kinds
([`sql.py:86-90`](../../../warden/broker/adapters/sql.py),
[`http.py:41-46`](../../../warden/broker/adapters/http.py),
[`docstore.py:41-46`](../../../warden/broker/adapters/docstore.py),
[`mail.py:39-44`](../../../warden/broker/adapters/mail.py)), which
`warden config check` already reports on when it is missing.

The class is **monotonic under failure but not under refusal**, and the
asymmetry is the point — each direction is the fail-closed one:

- **Policy denied, or the audit write failed:** the class is dropped with the
  reservation. Nothing ran, and nothing was read. Keeping it would let one
  refused PII read poison a task for the rest of its life, which an agent could
  trip on purpose.
- **`execute()` raised:** the class is kept, the rows are released. The adapter
  reached the source and may have received bytes before failing; the budget
  should not pay for a backend outage (A4), but the taint should not be
  forgotten because the connection dropped late.

**`charge` returns the state before its own charge, and that is load-bearing.**
It is what feeds the policy input and the audit record, exactly as `snapshot()`
does today. A snapshot that included the caller's own class would make a task's
first PII read through an HTTP tool trip `egress.pii_sink` and deny *itself*.

### 4 · Reservations carry an identity and a deadline

Each charge writes an identified reservation with an absolute deadline; the
charged total is `committed + Σ(live reservations)`; every charge prunes
expired ones before it sums. A broker killed between charge and reconcile
self-heals in bounded time.

*Rejected:* a single counter, with leaks cleared only when A5 evicts the whole
task. It fails closed, but task state deliberately outlives the token
([README.md:266-267](../../../README.md) — renewing does not reset it), so on a
long task the leak is effectively permanent, and an ordinary rolling restart
would silently narrow every in-flight task's budget for the rest of its life.
*Also rejected:* treating a token renewal as a barrier that zeroes
reservations — nothing stops a call from the previous token being in flight, so
it can hand the budget back to a call that is still running.

The deadline also licenses decision 6's error handling, and gives D2 a real
"reservations in flight per task" metric for free.

### 5 · The field is renamed to `rows_charged_so_far`

The number is a different quantity, and a **non-monotonic** one: call A records
`0`, a concurrent call B records `50` (A's reservation), then A returns 3 rows
and the next call records `3`. A reader of the audit log sees 0 → 50 → 3 under
a field named "returned so far", in the one artifact whose whole pitch is that
it says what really happened.

Version skew then fails closed in **both** directions, which is the deciding
argument. A policy reading the old name gets `null` from its `default`
accessor and denies `input.malformed`
([`authz.rego:112`](../../../warden/policies/authz.rego)); a new policy against
an old broker denies the same way. Nothing silently under-counts.

*Rejected:* keeping the old name and documenting the change — zero churn, but a
field name that is wrong during every in-flight window. *Also rejected:*
keeping `rows_returned_so_far` as committed-only and adding `rows_reserved`
for R5 to sum. That is the fail-**open** option: a deployment running a custom
policy that has not added the third term keeps evaluating, keeps ignoring
reservations, and the hole § A exists to close stays open with no error
anywhere.

The policy input and the audit record keep carrying **one** dict, as
[`spine.py:194-196`](../../../warden/broker/spine.py) does today. They cannot
diverge without destroying `tests/golden/decisions/`'s ability to reconstruct
the decision a record describes.

### 6 · A store failure refuses; a deadline covers the rest

The in-memory store cannot fail, but the interface must say what a failing one
means, or A2 will invent it:

| When | Behaviour | Why |
|---|---|---|
| `charge` raises | Refuse, record nothing, render 503 | Nothing has happened yet, and this system refuses when it cannot decide |
| `reconcile` raises | Post-execute fault carrying the durable allow's `seq` | The action happened; a caller must not retry, and the existing `AFTER_EXECUTE` rendering says exactly that |
| `release` / `abandon` raises | Swallowed | The reservation's deadline already collects it — this is what decision 4 buys |

Two new `Kind` members — `STATE_UNAVAILABLE_ON_CHARGE` and
`STATE_UNAVAILABLE_AFTER_EXECUTE` — mapped into the `AUDIT_UNAVAILABLE` and
`AFTER_EXECUTE` rendering groups respectively, so neither invents a new status
code or message. Both are reachable in tests through a fake store that raises,
so neither is untested dead code.

Recording nothing on a charge failure follows the two precedents already in the
file rather than inventing a third rule: `DESCRIBE_BACKEND_FAULT` records
nothing because the fault is "a server bug, not the agent's doing", and
`AUDIT_UNAVAILABLE_ON_ALLOW` records nothing because the write itself is what
failed. A store the broker cannot reach is the first of those and renders like
the second.

---

## The interface

```python
class TaskStateStore(Protocol):
    def charge(self, task_id: str, *, charge_id: str, rows: int,
               data_class: str | None, now: int, expires_at: int) -> dict: ...
    def reconcile(self, task_id: str, charge_id: str, *, rows: int,
                  data_class: str | None, now: int) -> None: ...
    def release(self, task_id: str, charge_id: str, *, now: int) -> None: ...
    def abandon(self, task_id: str, charge_id: str, *, now: int) -> None: ...
    def peek(self, task_id: str, *, now: int) -> dict: ...
```

- **One charge, three endings.** `reconcile` (succeeded: commit the actual rows,
  keep the class), `release` (never ran: drop rows *and* class), `abandon` (ran
  and failed: drop rows, keep class). A single `settle(keep_class: bool)` would
  hide the one asymmetry a reader most needs to see.
- **`charge_id` and `now` are caller-supplied.** Redis Lua scripts must be
  deterministic, so `uuid4()` and a clock read inside the script are not
  available to A2. Generating both at the call site keeps one interface honest
  to both implementations, and matches the injected-clock discipline in
  [`spine.py:143-148`](../../../warden/broker/spine.py) — expiry tests then need
  no `sleep`.
- **`reconcile` re-unions the class** it was already charged. Redundant today,
  since every adapter derives `ToolResult.data_class` and its binding class from
  the same value; it keeps a future adapter that discovers a class at execute
  time from silently losing it. Belt-and-braces in the fail-closed direction.
- **`snapshot()` disappears.** `charge` creates the entry it is about to spend
  from, so the phantom-entry hazard `TaintTracker.snapshot`'s docstring
  documents is gone from the serving path entirely. `peek` keeps its
  non-creating contract verbatim, and `Spine.task_state` still reads through it.
- **`data_class` reaches the spine through a new `ToolCatalog.data_class(tool)`.**
  It stays out of `ToolTarget`: the policy input document is an interface, and
  no rule judges the class a call will *produce*.
- **`expires_at` is passed in** (the spine computes `token.exp + grace`, a token
  fact); **the in-flight deadline is store config** (a recovery mechanism, not a
  token fact).

### The shape A2 must implement

Stated here so the contract is known to be implementable in one atomic step,
not discovered later. `charge` is one script over one key per task:

```
prune reservations whose deadline <= now
pre := {committed, classes}                 # snapshot BEFORE this charge
write reservation charge_id -> (rows, deadline = now + max_in_flight)
add data_class to classes                   # no-op when the tool declares none
set key expiry to max(current, expires_at)
return pre
```

`pre.rows_charged_so_far` is `committed + Σ(live reservations)` counted *before*
this call's own reservation is written — other callers' in-flight rows are in
it, this caller's are not. That is the whole of decision 3's "cannot deny
itself", expressed as one line of ordering inside the script.

Deterministic given caller-supplied `charge_id` and `now`; one round trip;
no limit anywhere in it.

## The sequence, with every exit

```
describe ──▶ charge ──▶ decide ──┬─ deny ──────────────▶ release
                                 └─ allow ──▶ append ──┬─ OSError ─▶ release
                                                       └─ ok ──▶ execute ──┬─ raise ─▶ abandon
                                                                           └─ ok ────▶ reconcile
```

Everything before `describe()` — authentication, a malformed body, a schema
rejection, an unknown tool, a `describe()` fault — is unchanged and takes no
charge, because there is no estimate to charge yet. Those paths read state
through `peek` at the point of denial, rather than through today's single
up-front `snapshot()`.

That relocation preserves the invariant the current
[`spine.py:194-196`](../../../warden/broker/spine.py) comment protects — the
decision and the record must never see different state — and strengthens it.
On the charge path there is exactly one read, `charge`'s return, feeding both
the policy input and the audit record. On a pre-describe denial there is no
decision at all, only a record, so a single `peek` is the whole of it. No path
reads twice.

**Charging before the audit write does not weaken "the decision is written down
before anything happens".** A reservation is bookkeeping. It is invisible to
the world except as strictness against the task's own budget, and it is
released on every path that does not act.

**A negative row count** (`TAINT_REJECTED_AFTER_EXECUTE`) reconciles at the
*estimate* rather than leaving state untouched as today. A buggy adapter should
cost what was authorised, not nothing. Deliberate change; the outcome the
caller sees is unchanged.

## Expiry

Two independent clocks, and conflating them is the mistake this section exists
to prevent:

| | Bounds | Default | Purpose |
|---|---|---|---|
| Reservation deadline | `now + max_in_flight_seconds` | 60s | Collects a charge whose broker died |
| Task state lifetime | `max(current, token.exp + ttl_grace_seconds)` | 3600s grace | Closes the unbounded-growth leak (A5) |

60s is six times the shared `httpx.Client(timeout=10.0)` in
[`__main__.py:112`](../../../warden/broker/__main__.py) that bounds every
HTTP-shaped `execute()`, and comfortably above SQLite's local read. It must
exceed the slowest `execute()`, or a live call's reservation is collected while
it runs, handing its budget to a concurrent caller.

The grace period is a real trade and gets said out loud: task state deliberately
survives token renewal, so eviction can only key off the *last* token's expiry
plus a grace. A task idle for longer than `token.exp + grace` loses its budget
and its held classes; an orchestrator that then re-mints the same `task_id` gets
a clean task. With a 300s token TTL and a 3600s grace, that is roughly an hour
of silence. A deployment that wants state to persist longer raises the grace and
pays in memory; C3 (revocation) is the right control for ending a task *now*,
not this.

New optional `[task_state]` section in `warden.toml`, alongside the existing six
— `_optional_section` and `_integer` already exist in the loader for exactly
this shape:

```toml
[task_state]
max_in_flight_seconds = 60
ttl_grace_seconds = 3600
```

## What changes where

| File | Change |
|---|---|
| `warden/broker/taint.py` | `TaskStateStore` protocol + `InMemoryTaskStateStore`; internal `threading.Lock` (the spine's synchrony is no longer the lock) |
| `warden/broker/spine.py` | The sequence above; two new `Kind` members; `_empty_state()` renamed field |
| `warden/broker/config/catalog.py` | `data_class(tool)` accessor |
| `warden/broker/config/loader.py` | `[task_state]` section → `TaskStateConfig` |
| `warden/broker/app.py`, `wiring.py`, `__main__.py` | Construct and thread the store; render the two new kinds. `Spine.__init__`'s new parameters are annotated on the way past — P1's carried debt is that the *existing* collaborators are not, and this spec neither fixes that (F1b's job) nor adds to it |
| `warden/broker/proxy.py` | Two literal `task_state` dicts renamed (`:108`, `:169`) |
| `warden/policies/authz.rego` | Field rename only: the `safe_*` accessor, R5, the malformed guard |
| `warden/policies/authz_test.rego` | Every `task_state` literal |
| `tests/golden/decisions/*.json` | Every input document |
| `tests/golden/audit-4711.jsonl`, `replay-4711.txt` | Regenerated from a cassette-mode `protected` run — the chain hashes cover the renamed field, and `tests/golden/README.md` requires the commit message to say the change was intended |
| `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md` | The semantics change, and the "row budget is only safe with one worker" limitation |

## How each property is proven

The suite being green has repeatedly not been evidence in this repository, so
each property below names the mutation that must break it. A test that does not
fail when its guard is removed is not a test.

| Property | Test | Mutation that must turn it red |
|---|---|---|
| Exactly-once budget under concurrency | N threads call `handle_tool_call` for one `task_id` against a PDP stub that blocks between describe and decide; assert exactly the prefix that fits is allowed | Replace `charge` with read-then-write, or have the spine `peek` instead of charging |
| A denied call taints nothing | Deny a PII read by rule; assert `peek` shows no class | Make `release` keep the class |
| A failed `execute()` keeps the class, releases the rows | Adapter raises; assert the class is held and `rows_charged_so_far` is back to its prior value | Swap `abandon` for `release` |
| A call cannot deny itself | First PII read through an HTTP tool to an unapproved host; assert it is not denied by `egress.pii_sink` | Make `charge` return the post-charge state |
| Leaked reservation self-heals | Charge, never settle, advance the injected clock past the deadline, assert the budget is whole | Remove the prune step |
| Task state survives renewal, dies after grace | Two charges with different `token.exp`; assert extension, then expiry | Set `expires_at` instead of `max(current, expires_at)` |
| Store failure refuses rather than acts | Fake store raising on `charge`; assert 503 and that `execute()` never ran | Catch and continue |
| Sequential runs are arithmetically unchanged | The existing golden decision corpus and `report` scenario figures | — (this one must *not* move) |

`opa test`, the decision corpus and the replay pair each keep their existing
roles, which `tests/golden/README.md` documents and which the rename does not
change.

## What this does not do

- **A2, the Redis store.** Its shape is pinned above so the interface is known
  to admit it, but connection config, a compose service, and — the real design
  question — what the broker does when Redis is *unreachable* deserve their own
  argument. Decision 6 fixes the contract that argument has to satisfy.
- **A6, the async spine.** It rewrites the concurrency assumption
  `spine.py`'s docstring is built on and touches `proxy.py` too. Reviewing it
  alongside a state-accounting change means neither gets read carefully. Note
  the ordering consequence: until A6 lands, the in-process serialisation still
  holds, so this work is proven by tests rather than exercised by production
  traffic. That is the intended order — the accounting must be right before the
  thing that makes it necessary is switched on.
- **Multi-worker deployment.** Needs A2 and B6 (audit sequencing); this spec
  changes no deployment topology.
- **A denial budget (D6), metrics (D2), revocation (C3).** Named here only
  because reservations make each cheaper later.
