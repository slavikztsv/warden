# P2·A2 — the shared task-state store, in Redis

**Status:** approved design, spiked against a live server before being written
**Sequenced by:** [docs/ROADMAP.md](../../ROADMAP.md) § A, item A2 — the last
one open in that section.
**Covers:** A2 only.
**Deliberately does not cover:** B6, the process model, and therefore § A's exit
criterion. See *What this does not do*.
**Verified against:** a real `redis:7-alpine` (7.4.10) on a throwaway
container and `redis-py` 6.4.0, driving `tests/warden/test_task_state.py`'s own
cases. Every number below was measured on that setup, not reasoned about.

---

## What this is

`InMemoryTaskStateStore` makes a task's budget safe inside one process.
[README.md](../../../README.md)'s limitation is that two brokers keep two
budgets, and A6 has now removed the throughput reason to run only one — which
leaves the store as the single thing standing between this and more than one
worker.

This document is written **after** a working implementation rather than before
one, and that is a deliberate departure. The design space had fifteen known
landmines from an adversarial review, four of them in the *existing* P2·A
spec's own pseudocode, and a live Redis is an oracle that settles them in
minutes. Two of the five decisions below were discovered by the spike failing,
not by argument. Writing them down first would have shipped both.

---

## The five decisions

### 1 · The key TTL is relative, and it is only a garbage collector

**Measured, not reasoned: the first spike deleted the key on every charge.**
The suite drives `now=1000` against `expires_at=10**9` — "far past any `now`
these tests use", says its own comment, and September 2001 in real time.
`EXPIREAT` runs on **Redis's wall clock**; `expires_at` is on **whatever clock
the caller injected**. Those are the same clock in production, where the spine
passes `int(time.time())`, and are not the same clock anywhere else.

So the script writes `EXPIRE key (x - now)` — the absolute logical instant
turned into a duration, which is correct on both clocks.

The deeper rule this enforces: **the key's own TTL never decides anything.**
Liveness is the `x` field compared against the caller's `now`, exactly as
`_live()` and not `_sweep()` decides it in
[taint.py](../../../warden/broker/taint.py). Redis's expiry is the
`_sweep` analogue — the thing `taint.py:249-250` already calls an
optimisation.

*Rejected:* `PEXPIREAT`, which the adversarial review flagged and which is
worse than wrong-in-tests: `expires_at` is seconds, so milliseconds reads it as
a timestamp deep in the past and deletes the key immediately, silently, in
production too. *Also rejected:* reading `redis.call('TIME')` inside the
script. It is permitted — verified, contrary to the premise recorded in
`taint.py:68-70` — but it would put the store on a third clock, and the whole
reason `now` is caller-supplied is so expiry tests need no `sleep`.

### 2 · Validate before mutating, because Redis does not roll back

Verified against 7.4.10: a script that writes and then errors **leaves the
write behind**. There is no transaction to abort.

That matters more here than anywhere, because the spine reports a failed
`charge` as `STATE_UNAVAILABLE_BEFORE_EXECUTE`, whose whole contract is
*"every path it covers has acted on nothing"*
([spine.py:69-72](../../../warden/broker/spine.py)). A script that half-ran
would make that sentence false.

So every script does all of its validation first and all of its writes after,
with no interleaving. Concretely: `charge` checks the duplicate `charge_id`
before it writes anything, and `reconcile` rejects a negative row count in
**Python**, before the script is sent at all.

### 3 · The class lives on the reservation; `k:` is committed-only

One hash per task:

```
c            committed rows, an integer
x            expires_at, epoch seconds, on the caller's clock
k:<class>    a class some SETTLED call committed
r:<id>       a live reservation, "<rows>:<deadline>:<class>"
```

The reservation carries its own class. `release` then drops the class it
claimed by dropping the reservation, and cannot touch one a settled call
committed — correct by construction rather than by bookkeeping.

This is the decision the existing P2·A spec gets **wrong**: its pseudocode says
`add data_class to classes` at charge time
([the P2·A spec:275](2026-08-06-p2a-task-state-store-design.md)), which is the
single per-task class set that
[`taint.py:36-45`](../../../warden/broker/taint.py) records as tried and
abandoned — *"that reasoning is wrong for a zero-row read, because a mail send
legitimately commits a class while committing no rows."* An implementer
following that line writes `k:<class>` in `charge`, `release` cannot remove it,
and **one policy-denied PII read permanently taints the task** — the
agent-trippable poisoning [spine.py:333-336](../../../warden/broker/spine.py)
exists to prevent. That spec is corrected as part of this work.

One hash, not a hash plus a set, so the whole of a task's state shares one
expiry and one cluster slot.

### 4 · Retries are off, and the socket timeout is bounded

`redis-py` 6.4.0 defaults to `Retry(retries=3)` over `ConnectionError` and
`TimeoutError`, and to `socket_timeout=None`. Both defaults are wrong here, and
both were measured.

**Retries off.** `charge` is deliberately anti-idempotent: a duplicate
`charge_id` is an error. So a retry after a lost reply — precisely the case
where the script already ran — hits that guard and turns a transient blip into
a *guaranteed* refusal, plus an orphan reservation. Worse, `reconcile`'s
`HINCRBY` is not idempotent at all: three retries commit the rows three times,
and the budget is then wrong, fail-closed but arithmetically false, for the
task's whole life.

Doing nothing is the right answer, and it is already paid for: a lost `charge`
leaves a reservation that its **deadline** collects within
`max_in_flight_seconds`. That mechanism exists for exactly this
([the P2·A spec, decision 4](2026-08-06-p2a-task-state-store-design.md)), and
the call itself refuses through a contract that is already written.

**A bounded `socket_timeout`.** `None` means a hung Redis blocks the calling
thread forever — and since A6 those threads are a pool of 16 shared with the
egress proxy, so an unreachable-but-not-refusing Redis would exhaust the
broker rather than fail it. Default 2s, configurable, and refused at boot if it
is not less than `max_in_flight_seconds`: a store call that could outlive the
reservation it is taking is a contradiction.

### 5 · The proxy's failure path is a hole, and it is fixed here

`redis.exceptions.TimeoutError` **is not an `OSError`** — verified. Today
[`proxy.py`](../../../warden/broker/proxy.py)'s ladder is `except OSError` →
`audit.unavailable`/503, then `except Exception` → `proxy.error`/403. A Redis
outage therefore lands in the second branch, which returns **403 with no audit
record at all** — in the component whose stated reason for existing is that
*"denying without recording is the one failure mode this component cannot
have"*.

The store raises one type the proxy can name, and the proxy grows a branch for
it that refuses **and records**, like every other refusal it writes. This is a
defect in the shipped contract that A2 exposes rather than creates; it is
fixed here because A2 is what makes it reachable.

---

## The contract, unchanged

The five methods, the three endings, the caller-supplied `charge_id` and `now`
are all exactly as
[the P2·A spec](2026-08-06-p2a-task-state-store-design.md) fixed them. A
`ResponseError` from the duplicate guard is translated to `ValueError` in
Python, because the interface says `ValueError` and no caller should have to
know which store it is talking to.

Return values are a **flat array**, never `cjson`, and `sorted()`/`int()` are
applied in Python. Three reasons, each measured or checked:

- Redis's bundled cjson encodes an **empty table as `{}`**, while fakeredis
  encodes it as `[]`. A contract suite on fakeredis would be green while
  production denied every call on `authz.rego`'s `is_array` guard.
- Lua's `table.sort` on strings compares with `strcoll`, which is
  locale-dependent. Python's sort is not.
- `authz.rego` denies `input.malformed` unless `rows_charged_so_far`
  `is_number`, and RESP bulk strings arrive as `bytes`.

## Configuration

```toml
[task_state]
backend = "memory"          # or "redis"
url = "${REDIS_URL}"        # required when backend = "redis"
socket_timeout_seconds = 2
```

`memory` stays the default, so every existing deployment and the whole demo
keep working with no Redis at all. `url` goes through the loader's existing
`interpolate`, so a password stays out of the mounted TOML and an unset
variable fails at boot rather than at the first request.

## How each property is proven

The suite being green has repeatedly not been evidence here, so each property
names the mutation that must break it. Every row below has already been run
against 7.4.10 during the spike.

| Property | Test | Mutation that must turn it red | Spike result |
|---|---|---|---|
| The Redis store satisfies the same contract | `tests/warden/test_task_state.py` parametrized over both stores | any semantic divergence | **23/23 passing** |
| Concurrent charges are ordered exactly once | 20 threads, one task, distinct pre-states | replace the single `EVAL` with peek-then-write | **atomic 20/20 distinct; mutant 9/20** |
| **Two brokers share one budget** | Ten charges alternating across two independent clients | point the two at different Redis DBs | **prefix [0,10..90], shared total 100** |
| `peek` creates nothing | Peek an id never charged; assert no key exists | let `peek` run the eviction prelude | **no key created** |
| An evicted task starts clean | Charge past `x`; assert the pre-state is zero | drop the prelude's `DEL` | passing |
| A settle cannot resurrect an evicted task | Reconcile a task past `x`; assert no key | drop the `EXISTS` guard (`HINCRBY` auto-creates, with no `x`, so no TTL — an immortal key) | passing |
| The key TTL never collects a live task | Charge with a logical clock far from wall time | `EXPIREAT` instead of `EXPIRE` | **caught the real bug** |
| A store outage refuses and RECORDS on the proxy | Unreachable Redis; assert 503 **and** an audit record | catch it as `except Exception` | to build |
| Sequential runs are unchanged | The golden corpus and `warden-demo explain` | — (must *not* move) | to run |

## What this does not do

- **§ A's exit criterion.** "Four workers behind a load balancer" needs A2 **and**
  B6 **and** a process model that does not exist: there is no `healthz`, no
  `readyz`, no `SO_REUSEPORT`, and `__main__.py` binds the proxy inside the same
  `asyncio.run` as uvicorn. A2 is one of three, and the roadmap should say so
  rather than implying this closes it.
- **B6, the audit chain.** `seq` is still allocated under a process-local lock,
  so two brokers writing one audit file still break the chain. A2 makes B6
  cheaper — same client, same key namespace, same failure contract — and does
  not do it.
- **❌ Production.** Does not move. Phase 3 is still the gate.
- **Redis Cluster, Sentinel, or TLS to Redis.** One connection to one server.
  The key layout is single-key-per-operation, so cluster is a config question
  later rather than a redesign.
