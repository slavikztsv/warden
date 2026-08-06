# P2·A Task State Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the process-local, read-then-write row budget with a
`TaskStateStore` whose charge is atomic, whose reservations expire, and whose
number means "rows charged" rather than "rows returned".

**Architecture:** `describe()` prices a call, `charge` reserves that price
atomically and returns the state *before* it, OPA judges that pre-state with
unchanged arithmetic, and exactly one of `reconcile` / `release` / `abandon`
settles the reservation. Each reservation carries an absolute deadline so a
broker that dies mid-call self-heals. The in-memory store is the only
implementation here; the interface is shaped so A2's Lua script is a drop-in.

**Tech Stack:** Python 3.12, FastAPI, `threading.Lock`, OPA/Rego, pytest,
`ruff`, `mypy` (non-strict over `warden/`).

**Spec:** [2026-08-06-p2a-task-state-store-design.md](../specs/2026-08-06-p2a-task-state-store-design.md)

## Global Constraints

- **Branch:** `p2a-task-state-store`. Every task ends in a commit; the tree is
  green at every commit.
- **The gate is:** `ruff check .`, `mypy warden/`, `pytest`, `opa test warden/policies/ demo/scenario/data.json`.
  All four pass before any commit. Expect **722** tests collected — 638 means
  the `mcp` extra is missing from the venv, not that tests vanished.
- **The `.venv` cannot be recreated in this environment.** Use it; do not
  `pip install -U` or rebuild it.
- **A green suite is not evidence.** Every property this plan adds names a
  mutation that must turn its test red. Apply the mutation, watch it fail,
  restore with `git checkout --`, confirm `git status` clean. Record the result
  in the commit message.
- **Field name:** `rows_charged_so_far` everywhere after Task 1. Zero
  occurrences of `rows_returned_so_far` may survive outside prose that
  deliberately quotes the old name.
- **No `sleep` in tests.** Time is injected: the store takes `now` from its
  caller, the spine from its existing injected clock.
- **`tests/golden/audit-4711.jsonl` is never hand-edited.** It is regenerated
  from a real cassette-mode `protected` run, and the commit message says the
  change was intended (`tests/golden/README.md`).

---

## File Structure

| File | Responsibility |
|---|---|
| `warden/broker/taint.py` | **Rewritten.** `TaskStateStore` protocol, `InMemoryTaskStateStore`, `_TaskState`, `_Reservation`. Owns charging, settling, pruning and eviction. Nothing else in the tree knows what a reservation is. |
| `warden/broker/spine.py` | The sequence. Gains `charge`/settle calls, two `Kind` members, `_peek`, `_settle`. |
| `warden/broker/config/catalog.py` | Gains `data_class(tool)` — the one accessor the spine needs to charge a class before `execute()`. |
| `warden/broker/config/loader.py` | Gains `TaskStateConfig` and the optional `[task_state]` section. |
| `warden/broker/wiring.py`, `app.py`, `__main__.py`, `proxy.py` | Construct and thread the store; `taint=` becomes `task_state=`. |
| `warden/policies/authz.rego` | Field rename only. |
| `tests/warden/test_task_state.py` | **New.** Replaces `test_taint.py`. Store unit tests, expiry, concurrency. |

---

### Task 1: Rename the field, semantics untouched

A pure mechanical rename, landed alone so the behavioural diff that follows is
readable. Nothing about what the number *means* changes in this task.

**Files:**
- Modify: `warden/broker/taint.py`, `warden/broker/spine.py:95`,
  `warden/broker/proxy.py:108`, `warden/broker/proxy.py:169`
- Modify: `warden/policies/authz.rego:80-82`, `:92-94`, `:112`, `:258-259`, `:350`
- Modify: `warden/policies/authz_test.rego` (every `task_state` literal)
- Modify: `tests/warden/test_taint.py`, `tests/golden/decisions/*.json`
- Regenerate: `tests/golden/audit-4711.jsonl`, `tests/golden/replay-4711.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: the key `rows_charged_so_far` in every task-state dict — policy
  input, audit record, `peek`/`snapshot` return.

- [ ] **Step 1: Confirm the pre-state and get a baseline**

```bash
grep -rn "rows_returned_so_far" --include='*.py' --include='*.rego' --include='*.json' . | grep -v '\.venv' | wc -l
.venv/bin/pytest -q 2>&1 | tail -3       # expect 722 collected, all pass
opa test warden/policies/ demo/scenario/data.json   # expect PASS 53/53
```

- [ ] **Step 2: Rename in source and policy**

```bash
grep -rlZ "rows_returned_so_far" --include='*.py' --include='*.rego' --include='*.json' \
  warden/ tests/ | xargs -0 sed -i 's/rows_returned_so_far/rows_charged_so_far/g'
```

Then check the rego's `safe_` accessor name came along:

```bash
grep -n "rows_charged_so_far\|safe_rows" warden/policies/authz.rego
```

Expected: `default safe_rows_charged_so_far := null`, its definition, the
`is_number` malformed guard, the negative guard, and R5's sum — five sites, no
`returned` left.

- [ ] **Step 3: Run the non-golden gates**

```bash
opa test warden/policies/ demo/scenario/data.json
.venv/bin/pytest -q tests/warden/test_taint.py tests/warden/test_app.py tests/warden/test_spine.py
```

Expected: `opa test` PASS; the three test files pass. `test_golden_decisions.py`
and `test_golden_replay.py` are expected to FAIL until Steps 4-5.

- [ ] **Step 4: Regenerate the golden audit chain**

The chain hashes cover the renamed field, so this file must be *produced*, not
edited (`tests/golden/README.md`). Cassette mode, `protected` profile, as the
README records:

```bash
docker --version                          # confirm Docker is available first
.venv/bin/warden-demo up --profile protected
```

Copy the produced log and replay over the goldens:

```bash
cp runs/<latest>/audit.jsonl tests/golden/audit-4711.jsonl
.venv/bin/warden replay 4711 --audit tests/golden/audit-4711.jsonl > tests/golden/replay-4711.txt
```

**If Docker is unavailable, stop and report it.** Do not hand-edit the chain
and do not rehash it in place — an edit is indistinguishable from tampering,
which is the property the file exists to demonstrate.

- [ ] **Step 5: Verify the goldens and the full gate**

```bash
.venv/bin/pytest -q 2>&1 | tail -3
ruff check . && .venv/bin/mypy warden/
grep -rn "rows_returned_so_far" --include='*.py' --include='*.rego' --include='*.json' . | grep -v '\.venv'
```

Expected: 722 pass, both linters clean, and the final `grep` prints nothing.

- [ ] **Step 6: Verify by mutation that the rename fails closed**

Prove the claim the rename was chosen for. Edit `warden/policies/authz.rego`'s
R5 to read the *old* key:

```rego
	total := input.task_state.rows_returned_so_far + input.target.estimated_rows
```

```bash
.venv/bin/pytest -q tests/warden/test_golden_decisions.py 2>&1 | tail -5
```

Expected: FAIL — and the failures must be *denials*, not allows, because the
`default safe_rows_charged_so_far := null` guard denies `input.malformed`.
Restore and confirm clean:

```bash
git checkout -- warden/policies/authz.rego && git status --short
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: rename rows_returned_so_far to rows_charged_so_far

Mechanical, ahead of the semantics change it is named for, so the
behavioural diff lands readable. The goldens are regenerated from a real
cassette-mode protected run, not edited -- intended, per
tests/golden/README.md.

Verified by mutation: pointing R5 back at the old key fails the decision
corpus with input.malformed denials rather than allows, which is the
fail-closed property the rename was chosen for."
```

---

### Task 2: `InMemoryTaskStateStore`

The store, fully tested, with no callers yet. `TaintTracker` stays until Task 4
so the tree is green at this commit.

**Files:**
- Modify: `warden/broker/taint.py`
- Create: `tests/warden/test_task_state.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `TaskStateStore` — Protocol with the five methods below.
  - `InMemoryTaskStateStore(max_in_flight_seconds: int = 60, sweep_interval_seconds: int = 60)`
  - `charge(task_id: str, *, charge_id: str, rows: int, data_class: str | None, now: int, expires_at: int) -> dict`
  - `reconcile(task_id: str, charge_id: str, *, rows: int, data_class: str | None, now: int) -> None`
  - `release(task_id: str, charge_id: str, *, now: int) -> None`
  - `abandon(task_id: str, charge_id: str, *, now: int) -> None`
  - `peek(task_id: str, *, now: int) -> dict`
  - Every dict returned is `{"data_classes_held": sorted list, "rows_charged_so_far": int}`.

- [ ] **Step 1: Write the failing tests**

Create `tests/warden/test_task_state.py`:

```python
"""The store's contract: what a charge is, and what settles it."""

from __future__ import annotations

import threading

import pytest

from warden.broker.taint import InMemoryTaskStateStore

NEVER = 10**9  # an expires_at far past any `now` these tests use


def store():
    return InMemoryTaskStateStore(max_in_flight_seconds=60)


def charge(s, task="4711", *, cid="c1", rows=0, data_class=None, now=1000):
    return s.charge(task, charge_id=cid, rows=rows, data_class=data_class,
                    now=now, expires_at=NEVER)


def test_a_fresh_task_is_clean():
    assert store().peek("4711", now=1000) == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }


def test_charge_returns_the_state_before_itself():
    """Load-bearing: a snapshot including the caller's own class would make a
    task's first PII read through an HTTP tool trip egress.pii_sink and deny
    itself."""
    s = store()
    pre = charge(s, rows=10, data_class="pii")
    assert pre == {"data_classes_held": [], "rows_charged_so_far": 0}


def test_a_reservation_is_visible_to_the_next_caller():
    s = store()
    charge(s, cid="c1", rows=10, data_class="pii")
    assert s.peek("4711", now=1000) == {
        "data_classes_held": ["pii"], "rows_charged_so_far": 10,
    }


def test_reconcile_swaps_the_estimate_for_the_actual():
    s = store()
    charge(s, cid="c1", rows=50, data_class="pii")
    s.reconcile("4711", "c1", rows=3, data_class="pii", now=1000)
    assert s.peek("4711", now=1000) == {
        "data_classes_held": ["pii"], "rows_charged_so_far": 3,
    }


def test_reconcile_commits_an_overshoot():
    """describe() and execute() use separate connections, so the table can
    grow between them. The rows exist; the next call pays for it."""
    s = store()
    charge(s, cid="c1", rows=5)
    s.reconcile("4711", "c1", rows=9, data_class=None, now=1000)
    assert s.peek("4711", now=1000)["rows_charged_so_far"] == 9


def test_release_drops_the_rows_and_the_class():
    """A denied call taints nothing -- otherwise one refused PII read poisons
    a task for the rest of its life, and an agent could trip that on purpose."""
    s = store()
    charge(s, cid="c1", rows=50, data_class="pii")
    s.release("4711", "c1", now=1000)
    assert s.peek("4711", now=1000) == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }


def test_abandon_drops_the_rows_and_keeps_the_class():
    """execute() reached the source and may have received bytes before it
    failed. The budget must not pay for a backend outage; the taint must not
    be forgotten because the connection dropped late."""
    s = store()
    charge(s, cid="c1", rows=50, data_class="pii")
    s.abandon("4711", "c1", now=1000)
    assert s.peek("4711", now=1000) == {
        "data_classes_held": ["pii"], "rows_charged_so_far": 0,
    }


def test_release_keeps_a_class_an_earlier_settled_call_committed():
    s = store()
    charge(s, cid="c1", rows=1, data_class="pii")
    s.reconcile("4711", "c1", rows=1, data_class="pii", now=1000)
    charge(s, cid="c2", rows=1, data_class="pii", now=1000)
    s.release("4711", "c2", now=1000)
    assert s.peek("4711", now=1000)["data_classes_held"] == ["pii"]


def test_a_leaked_reservation_expires():
    s = store()
    charge(s, cid="c1", rows=50, now=1000)
    assert s.peek("4711", now=1059)["rows_charged_so_far"] == 50
    assert s.peek("4711", now=1061)["rows_charged_so_far"] == 0


def test_settling_an_expired_reservation_is_a_no_op():
    s = store()
    charge(s, cid="c1", rows=50, now=1000)
    s.reconcile("4711", "c1", rows=50, data_class=None, now=1_000_000)
    assert s.peek("4711", now=1_000_000)["rows_charged_so_far"] == 0


def test_task_state_expires_and_is_evicted():
    s = store()
    s.charge("4711", charge_id="c1", rows=1, data_class="pii", now=1000,
             expires_at=2000)
    s.reconcile("4711", "c1", rows=1, data_class="pii", now=1000)
    assert s.peek("4711", now=1999)["rows_charged_so_far"] == 1
    assert s.peek("4711", now=2001) == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }


def test_a_later_charge_extends_the_lifetime_but_never_shortens_it():
    """Task state deliberately outlives one token: renewing must not reset the
    budget, and a shorter-lived token must not shorten what a longer one set."""
    s = store()
    s.charge("4711", charge_id="c1", rows=1, data_class=None, now=1000,
             expires_at=5000)
    s.reconcile("4711", "c1", rows=1, data_class=None, now=1000)
    s.charge("4711", charge_id="c2", rows=1, data_class=None, now=1100,
             expires_at=2000)
    s.reconcile("4711", "c2", rows=1, data_class=None, now=1100)
    assert s.peek("4711", now=4999)["rows_charged_so_far"] == 2


def test_peek_does_not_create_an_entry_for_an_unseen_task():
    """Spine.task_state and proxy.authorize_connect both read through here with
    an arbitrary id and no minted token behind it. Creating a phantom entry per
    id asked about would leak one forever."""
    s = store()
    assert s.peek("never-seen", now=1000) == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }
    assert "never-seen" not in s._tasks


def test_returned_state_is_not_a_live_view():
    s = store()
    charge(s, cid="c1", rows=1, data_class="pii")
    view = s.peek("4711", now=1000)
    view["data_classes_held"].append("exfiltrated")
    view["rows_charged_so_far"] = 999999
    assert s.peek("4711", now=1000) == {
        "data_classes_held": ["pii"], "rows_charged_so_far": 1,
    }


def test_tasks_are_isolated_from_each_other():
    s = store()
    charge(s, task="4711", rows=10, data_class="pii")
    assert s.peek("9999", now=1000) == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }


def test_data_classes_are_sorted_and_deduplicated():
    s = store()
    for i, cls in enumerate(["pii", "internal", "pii"]):
        charge(s, cid=f"c{i}", rows=0, data_class=cls)
    assert s.peek("4711", now=1000)["data_classes_held"] == ["internal", "pii"]


def test_a_negative_estimate_never_hands_budget_back():
    """R1b denies a negative estimated_rows as input.malformed, but the charge
    happens BEFORE that decision. Clamping at zero keeps a buggy adapter from
    opening a window in which a concurrent caller sees a smaller total."""
    s = store()
    charge(s, cid="c1", rows=100)
    charge(s, cid="c2", rows=-5_000_000)
    assert s.peek("4711", now=1000)["rows_charged_so_far"] == 100


def test_reconcile_rejects_a_negative_actual():
    s = store()
    charge(s, cid="c1", rows=1)
    with pytest.raises(ValueError):
        s.reconcile("4711", "c1", rows=-5, data_class=None, now=1000)


def test_a_duplicate_charge_id_is_rejected():
    s = store()
    charge(s, cid="c1", rows=1)
    with pytest.raises(ValueError):
        charge(s, cid="c1", rows=1)


def test_concurrent_charges_are_ordered_exactly_once():
    """The property the whole store exists for. Twenty threads charge 50 rows
    each against one task; the pre-state each one is handed must be a distinct
    multiple of 50, because a lost update is two callers seeing the same
    starting budget -- which is the TOCTOU this replaces."""
    s = store()
    seen: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker(i: int) -> None:
        barrier.wait()
        pre = s.charge("4711", charge_id=f"c{i}", rows=50, data_class="pii",
                       now=1000, expires_at=NEVER)
        with lock:
            seen.append(pre["rows_charged_so_far"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(seen) == [50 * i for i in range(20)]
    assert s.peek("4711", now=1000)["rows_charged_so_far"] == 1000
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
.venv/bin/pytest -q tests/warden/test_task_state.py 2>&1 | tail -5
```

Expected: collection error — `ImportError: cannot import name 'InMemoryTaskStateStore'`.

- [ ] **Step 3: Implement the store**

Append to `warden/broker/taint.py` (keep `TaintTracker` for now):

```python
import threading
from typing import Protocol


@dataclass
class _Reservation:
    rows: int
    deadline: int


@dataclass
class _Task:
    data_classes_held: set[str] = field(default_factory=set)
    rows_committed: int = 0
    reservations: dict[str, _Reservation] = field(default_factory=dict)
    expires_at: int = 0


class TaskStateStore(Protocol):
    """What the spine needs from task state, and nothing more.

    Every method takes `now` and `charge_id` from its caller rather than
    reading a clock or generating an id itself. That is not fastidiousness:
    a Redis implementation runs this logic inside a Lua script, and Redis
    requires scripts to be deterministic, so neither `time()` nor `uuid4()`
    is available inside one. Passing both in keeps a single interface honest
    to both implementations -- and, incidentally, makes every expiry test
    here run without a sleep.
    """

    def charge(self, task_id: str, *, charge_id: str, rows: int,
               data_class: str | None, now: int, expires_at: int) -> dict: ...
    def reconcile(self, task_id: str, charge_id: str, *, rows: int,
                  data_class: str | None, now: int) -> None: ...
    def release(self, task_id: str, charge_id: str, *, now: int) -> None: ...
    def abandon(self, task_id: str, charge_id: str, *, now: int) -> None: ...
    def peek(self, task_id: str, *, now: int) -> dict: ...


class InMemoryTaskStateStore:
    """The single-process store. One lock, held for the whole of every
    operation.

    The lock is what replaces the accident that used to make this safe:
    Spine.handle_tool_call contained no await and every collaborator blocked,
    so the broker served one call at a time and a read-then-write could not
    interleave. That was a property of the call graph, not of the state, and
    A6 dissolves it. This class does not depend on it.
    """

    def __init__(self, *, max_in_flight_seconds: int = 60,
                 sweep_interval_seconds: int = 60) -> None:
        self._tasks: dict[str, _Task] = {}
        self._lock = threading.Lock()
        self._max_in_flight = max_in_flight_seconds
        self._sweep_interval = sweep_interval_seconds
        self._next_sweep = 0

    def charge(self, task_id: str, *, charge_id: str, rows: int,
               data_class: str | None, now: int, expires_at: int) -> dict:
        with self._lock:
            self._sweep(now)
            task = self._live(task_id, now)
            if task is None:
                task = _Task()
                self._tasks[task_id] = task
            self._prune(task, now)
            if charge_id in task.reservations:
                raise ValueError(f"charge_id already in flight: {charge_id!r}")
            before = self._view(task)
            # max(rows, 0): a negative estimate is denied by R1b as
            # input.malformed, but that decision happens AFTER this charge.
            # Reserving a negative would hand budget back to whatever ran
            # concurrently, in the window before the denial released it.
            task.reservations[charge_id] = _Reservation(
                rows=max(rows, 0), deadline=now + self._max_in_flight
            )
            if data_class is not None:
                task.data_classes_held.add(data_class)
            # Never shortens: task state deliberately outlives one token, so a
            # short-lived renewal must not truncate what a longer one set.
            task.expires_at = max(task.expires_at, expires_at)
            return before

    def reconcile(self, task_id: str, charge_id: str, *, rows: int,
                  data_class: str | None, now: int) -> None:
        if rows < 0:
            raise ValueError(f"rows must be non-negative, got {rows}")
        with self._lock:
            task = self._settle(task_id, charge_id, now)
            if task is None:
                return
            task.rows_committed += rows
            # Re-unioned though charge() already added it. Redundant today,
            # because every adapter derives ToolResult.data_class and its
            # binding class from the same value; it keeps a future adapter
            # that discovers a class at execute time from silently losing it.
            if data_class is not None:
                task.data_classes_held.add(data_class)

    def release(self, task_id: str, charge_id: str, *, now: int) -> None:
        with self._lock:
            self._settle(task_id, charge_id, now)

    def abandon(self, task_id: str, charge_id: str, *, now: int) -> None:
        with self._lock:
            self._settle(task_id, charge_id, now)

    def peek(self, task_id: str, *, now: int) -> dict:
        """The same view charge() returns, WITHOUT creating an entry for a
        task_id that has never spent anything. Spine.task_state and
        proxy.authorize_connect both read through here with an id that may
        have no minted token behind it at all."""
        with self._lock:
            task = self._live(task_id, now)
            if task is None:
                return {"data_classes_held": [], "rows_charged_so_far": 0}
            return self._view(task, now=now)

    def _live(self, task_id: str, now: int) -> _Task | None:
        """The task, or None if it never existed or has expired. Expiry is
        checked here rather than left to the sweep, so correctness never
        depends on when the sweep last ran."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        if task.expires_at <= now:
            del self._tasks[task_id]
            return None
        return task

    def _sweep(self, now: int) -> None:
        """Drop every expired task, at most once per interval. A Redis store
        gets this from key TTLs; an in-process dict has to do it itself, and
        doing it per request would make every call O(live tasks)."""
        if now < self._next_sweep:
            return
        self._next_sweep = now + self._sweep_interval
        for task_id in [t for t, s in self._tasks.items() if s.expires_at <= now]:
            del self._tasks[task_id]

    def _settle(self, task_id: str, charge_id: str, now: int) -> _Task | None:
        task = self._live(task_id, now)
        if task is None:
            return None
        self._prune(task, now)
        # Not an error when absent: the deadline may have collected it first,
        # and a settle that raced its own expiry must not take the call down
        # after the action already happened.
        task.reservations.pop(charge_id, None)
        return task

    @staticmethod
    def _prune(task: _Task, now: int) -> None:
        for charge_id in [c for c, r in task.reservations.items() if r.deadline <= now]:
            del task.reservations[charge_id]

    @staticmethod
    def _view(task: _Task, *, now: int | None = None) -> dict:
        live = task.reservations.values()
        if now is not None:
            live = [r for r in live if r.deadline > now]
        return {
            "data_classes_held": sorted(task.data_classes_held),
            "rows_charged_so_far": task.rows_committed + sum(r.rows for r in live),
        }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
.venv/bin/pytest -q tests/warden/test_task_state.py 2>&1 | tail -3
```

Expected: 19 passed.

- [ ] **Step 5: Verify by mutation**

Three mutations, each restored with `git checkout -- warden/broker/taint.py`:

| Mutation | Must turn red |
|---|---|
| Delete `self._lock` usage in `charge` (replace `with self._lock:` with `if True:`) | `test_concurrent_charges_are_ordered_exactly_once` |
| `_view` returns `rows_committed` only (drop the reservation sum) | `test_a_reservation_is_visible_to_the_next_caller` |
| `abandon` calls the same body as `reconcile(rows=0)` but clears classes | `test_abandon_drops_the_rows_and_keeps_the_class` |

The first is the important one — run it repeatedly:

```bash
for i in 1 2 3 4 5; do .venv/bin/pytest -q tests/warden/test_task_state.py -k concurrent 2>&1 | tail -1; done
```

Expected under the mutation: FAIL on every run or nearly every run. If it
passes consistently, the test is not exercising the race — raise the thread
count and re-check before proceeding.

- [ ] **Step 6: Commit**

```bash
git add warden/broker/taint.py tests/warden/test_task_state.py
git commit -m "feat: add InMemoryTaskStateStore, with no callers yet

One charge, three endings: reconcile (succeeded), release (never ran),
abandon (ran and failed). Reservations carry an absolute deadline so a
broker killed mid-call self-heals; task entries carry an expiry so the
dict stops growing forever.

now and charge_id are caller-supplied because A2 runs this logic in a
Redis Lua script, where neither a clock read nor uuid4() is available.

Verified by mutation: removing the lock reddens the 20-thread ordering
test on every run; dropping the reservation sum from _view reddens the
visibility test; releasing the class on abandon reddens the taint test."
```

---

### Task 3: `ToolCatalog.data_class(tool)`

**Files:**
- Modify: `warden/broker/config/catalog.py`
- Modify: `tests/warden/test_catalog.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ToolCatalog.data_class(tool: str) -> str | None` — raises
  `UnknownTool` for a tool outside the catalog, exactly as `describe` does.

- [ ] **Step 1: Write the failing test**

Append to `tests/warden/test_catalog.py`:

```python
def test_data_class_reads_the_binding_not_the_result():
    """The spine charges a task's data class BEFORE execute() runs, so the
    class has to be knowable from config. It is: every adapter kind holds it
    as a binding property, which is why `warden config check` can already
    report a tool that declares none."""
    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path=DB_PATH,
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
    )
    assert catalog.data_class("read_customers") == "pii"


def test_data_class_of_an_unknown_tool_raises():
    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path=DB_PATH,
        mailer_url="http://mailer.internal",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
    )
    with pytest.raises(UnknownTool):
        catalog.data_class("no_such_tool")
```

Check the file's existing imports and fixture names first — reuse whatever
`test_catalog.py` already uses to build a catalog and to name the DB path
rather than introducing `DB_PATH` if a fixture already exists.

- [ ] **Step 2: Run it to verify it fails**

```bash
.venv/bin/pytest -q tests/warden/test_catalog.py -k data_class 2>&1 | tail -3
```

Expected: FAIL — `AttributeError: 'ToolCatalog' object has no attribute 'data_class'`.

- [ ] **Step 3: Implement**

In `warden/broker/config/catalog.py`, beside `describe`:

```python
    def data_class(self, tool: str) -> str | None:
        """The class this tool's reads carry, from its [binding].

        Read here rather than from ToolResult because the spine charges it
        before execute() runs. Deliberately NOT on ToolTarget: the policy
        input document is an interface, and no rule judges the class a call
        is about to produce -- only the ones a task already holds.
        """
        return self._entry(tool).adapter.data_class
```

- [ ] **Step 4: Run it to verify it passes**

```bash
.venv/bin/pytest -q tests/warden/test_catalog.py 2>&1 | tail -3
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add warden/broker/config/catalog.py tests/warden/test_catalog.py
git commit -m "feat: expose a tool's declared data class from the catalog

The spine charges the class before execute() runs, so it has to come from
config rather than from ToolResult. Kept off ToolTarget on purpose: the
policy input document is an interface, and no rule judges the class a call
is about to produce."
```

---

### Task 4: `[task_state]` configuration

**Files:**
- Modify: `warden/broker/config/loader.py`
- Modify: `tests/warden/test_config_loader.py`
- Modify: `demo/scenario/warden.toml`

**Interfaces:**
- Consumes: nothing.
- Produces: `TaskStateConfig(max_in_flight_seconds: int = 60, ttl_grace_seconds: int = 3600)`,
  reachable as `BrokerConfig.task_state`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_config_loader.py`, following that file's existing
helper for writing a TOML file and loading it:

```python
def test_task_state_defaults_when_the_section_is_absent(tmp_path):
    """Optional, like [mcp]. Every existing deployment's warden.toml predates
    this section and must keep loading."""
    config = load_broker_config(_write_minimal_toml(tmp_path), {})
    assert config.task_state.max_in_flight_seconds == 60
    assert config.task_state.ttl_grace_seconds == 3600


def test_task_state_values_are_read(tmp_path):
    path = _write_minimal_toml(
        tmp_path,
        extra="[task_state]\nmax_in_flight_seconds = 90\nttl_grace_seconds = 120\n",
    )
    config = load_broker_config(path, {})
    assert config.task_state.max_in_flight_seconds == 90
    assert config.task_state.ttl_grace_seconds == 120


def test_a_non_integer_task_state_value_is_rejected(tmp_path):
    path = _write_minimal_toml(
        tmp_path, extra='[task_state]\nmax_in_flight_seconds = "soon"\n'
    )
    with pytest.raises(ConfigError):
        load_broker_config(path, {})
```

- [ ] **Step 2: Run to verify they fail**

```bash
.venv/bin/pytest -q tests/warden/test_config_loader.py -k task_state 2>&1 | tail -3
```

Expected: FAIL — `AttributeError: 'BrokerConfig' object has no attribute 'task_state'`.

- [ ] **Step 3: Implement**

In `warden/broker/config/loader.py`:

```python
@dataclass(frozen=True)
class TaskStateConfig:
    """Two independent clocks, and conflating them is the mistake this type
    exists to prevent.

    max_in_flight_seconds bounds ONE call: it is the deadline on a
    reservation, and it collects a charge whose broker died before it could
    settle. It must exceed the slowest execute(), or a live call's budget is
    handed to a concurrent caller while it is still running. The default is
    six times the shared httpx.Client(timeout=10.0) in broker/__main__.py
    that bounds every HTTP-shaped adapter.

    ttl_grace_seconds bounds a whole TASK, and only exists because task state
    deliberately survives token renewal -- so eviction can key off nothing
    but the last token's expiry, plus a grace. A task silent for longer than
    that loses its budget and its held classes, and an orchestrator re-minting
    the same task_id afterwards gets a clean task. Raise it to keep state
    longer, and pay in memory; C3 (revocation) is the control for ending a
    task NOW.
    """

    max_in_flight_seconds: int = 60
    ttl_grace_seconds: int = 3600
```

Add `task_state: TaskStateConfig = TaskStateConfig()` to `BrokerConfig` (after
`mcp`, keeping defaulted fields last), and in `load_broker_config`:

```python
    task_state = _optional_section(document, "task_state")
```

```python
        task_state=TaskStateConfig(
            max_in_flight_seconds=(
                _integer(task_state, "task_state", "max_in_flight_seconds")
                if "max_in_flight_seconds" in task_state else 60
            ),
            ttl_grace_seconds=(
                _integer(task_state, "task_state", "ttl_grace_seconds")
                if "ttl_grace_seconds" in task_state else 3600
            ),
        ),
```

Then add the section to `demo/scenario/warden.toml` with both values at their
defaults, so the shipped config documents the knobs rather than hiding them.

- [ ] **Step 4: Run to verify they pass**

```bash
.venv/bin/pytest -q tests/warden/test_config_loader.py 2>&1 | tail -3
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add warden/broker/config/loader.py tests/warden/test_config_loader.py demo/scenario/warden.toml
git commit -m "feat: add the optional [task_state] section

Two clocks that are easy to confuse, so the dataclass docstring separates
them: max_in_flight_seconds bounds one call's reservation, ttl_grace_seconds
bounds a whole task's state. Optional, like [mcp], so every warden.toml
written before this section keeps loading."
```

---

### Task 5: Rewire the spine onto the store

The behavioural change. `TaintTracker` dies here.

**Files:**
- Modify: `warden/broker/spine.py`, `warden/broker/taint.py` (delete `TaintTracker`)
- Modify: `warden/broker/app.py`, `warden/broker/wiring.py`,
  `warden/broker/__main__.py`, `warden/broker/proxy.py`
- Delete: `tests/warden/test_taint.py`
- Modify: `tests/warden/test_app.py`, `tests/warden/test_spine.py`,
  `tests/warden/test_proxy.py`, `tests/warden/test_surface_parity.py`,
  `tests/warden/test_mcp_surface.py` (constructor keyword only)

**Interfaces:**
- Consumes: Task 2's store, Task 3's `data_class`, Task 4's config.
- Produces: `Spine(..., task_state=<TaskStateStore>, state_grace_seconds: int)`;
  `create_app(..., task_state=...)`; `Kind.STATE_UNAVAILABLE_BEFORE_EXECUTE`,
  `Kind.STATE_UNAVAILABLE_AFTER_EXECUTE`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_app.py`, using its existing `build()` helper and
`Clock`. Add a `task_state=` parameter to `build()` defaulting to a fresh
`InMemoryTaskStateStore()` so these can inject a fake:

```python
class ExplodingStore:
    """A store that fails where the test points it. A2's Redis store can be
    unreachable; this is how the spine's answer to that is pinned before the
    implementation that needs it exists."""

    def __init__(self, *, fail_on: str) -> None:
        self._real = InMemoryTaskStateStore()
        self._fail_on = fail_on

    def __getattr__(self, name):
        if name == self._fail_on:
            def boom(*args, **kwargs):
                raise RuntimeError("state store unreachable")
            return boom
        return getattr(self._real, name)


def test_a_denied_call_taints_nothing(tmp_path, signer):
    """One refused PII read must not poison a task for the rest of its life --
    an agent could otherwise trip that deliberately."""
    client, _ = build(tmp_path, signer, {"allow": False, "rule": "rows.bounded"})
    token = token_for(signer, allowed_tools=["read_customers"])
    client.post("/v1/tools/read_customers/invoke",
                json={"args": {"filter": "all"}},
                headers={"authorization": f"Bearer {token}"})
    spine = client.app.state.spine
    assert spine.task_state("4711") == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }


def test_a_failed_execute_keeps_the_class_and_releases_the_rows(tmp_path, signer):
    """The adapter reached the source and may have received bytes before it
    failed: the taint stays. The budget must not pay for a backend outage:
    the rows go back."""
    def backend(request):
        raise httpx.ConnectError("backend down")

    client, _ = build(tmp_path, signer, {"allow": True, "rule": "allow"},
                      backend_handler=backend)
    token = token_for(signer, allowed_tools=["read_document"])
    response = client.post("/v1/tools/read_document/invoke",
                           json={"args": {"doc_id": "ticket-4711"}},
                           headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 502
    state = client.app.state.spine.task_state("4711")
    assert state["rows_charged_so_far"] == 0
    assert state["data_classes_held"] == ["internal"]


def test_a_store_failure_before_execute_refuses_and_does_not_act(tmp_path, signer):
    executed = []

    def backend(request):
        executed.append(request.url)
        return httpx.Response(200, text="doc-body")

    client, audit = build(tmp_path, signer, {"allow": True, "rule": "allow"},
                          backend_handler=backend,
                          task_state=ExplodingStore(fail_on="charge"))
    token = token_for(signer, allowed_tools=["read_document"])
    response = client.post("/v1/tools/read_document/invoke",
                           json={"args": {"doc_id": "ticket-4711"}},
                           headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 503
    assert response.json()["error"] == "audit_unavailable"
    assert executed == []


def test_a_store_failure_after_execute_reports_the_durable_allow(tmp_path, signer):
    client, audit = build(tmp_path, signer, {"allow": True, "rule": "allow"},
                          task_state=ExplodingStore(fail_on="reconcile"))
    token = token_for(signer, allowed_tools=["read_document"])
    response = client.post("/v1/tools/read_document/invoke",
                           json={"args": {"doc_id": "ticket-4711"}},
                           headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 502
    assert "1" in response.json()["message"]  # the durable allow's seq


def test_a_first_pii_read_cannot_deny_itself(tmp_path, signer):
    """charge() returns the state BEFORE its own charge. If it returned the
    state after, this call would arrive at the PDP already holding "pii" and
    egress.pii_sink would refuse a task's very first read."""
    seen = []

    def opa_handler(request):
        seen.append(json.loads(request.content)["input"]["task_state"])
        return httpx.Response(200, json={"result": {"allow": True, "rule": "allow"}})

    client, _ = build(tmp_path, signer, None, opa_handler=opa_handler)
    token = token_for(signer, allowed_tools=["read_customers"])
    client.post("/v1/tools/read_customers/invoke",
                json={"args": {"filter": "customer:8812"}},
                headers={"authorization": f"Bearer {token}"})
    assert seen[0] == {"data_classes_held": [], "rows_charged_so_far": 0}
```

`build()` currently takes `opa_payload` and builds its own handler; add an
optional `opa_handler` parameter that overrides it, mirroring `build_with_mcp`,
which already has one.

Add to `tests/warden/test_spine.py`'s status table:

```python
        Kind.STATE_UNAVAILABLE_BEFORE_EXECUTE: 503,
        Kind.STATE_UNAVAILABLE_AFTER_EXECUTE: 502,
```

- [ ] **Step 2: Run to verify they fail**

```bash
.venv/bin/pytest -q tests/warden/test_app.py tests/warden/test_spine.py 2>&1 | tail -5
```

Expected: the new tests fail; `test_spine.py`'s totality test fails on the two
unknown `Kind` members.

- [ ] **Step 3: Implement the spine**

In `warden/broker/spine.py` — add to `Kind`:

```python
    STATE_UNAVAILABLE_BEFORE_EXECUTE = "state_unavailable_before_execute"
    STATE_UNAVAILABLE_AFTER_EXECUTE = "state_unavailable_after_execute"
```

Add the first to `AUDIT_UNAVAILABLE` and the second to `FAULT`, and name the
reason in the `FAULT` comment: like the other two, it leaves one durable allow
record for an action that already happened.

Replace `_empty_state`'s neighbours and `Spine.__init__`:

```python
    def __init__(
        self,
        *,
        verifier,
        pdp,
        task_state: TaskStateStore,
        audit,
        catalog,
        policy_digest: str,
        clock: Callable[[], int],
        state_grace_seconds: int = 3600,
    ) -> None:
```

New body for `handle_tool_call` (replacing the snapshot at the top and the
`record_read` at the bottom):

```python
    def handle_tool_call(
        self, credential: str | None, tool: str, args: dict | None
    ) -> Outcome:
        token, message = self._authenticate(credential)
        if token is None:
            return self._refuse({"type": "tool_call", "tool": tool}, message, Outcome)

        # One clock read for the whole call. Every store operation below --
        # the charge, its settlement, any peek -- must agree about what "now"
        # is, or a reservation can be pruned by the same call that took it.
        now = self._clock()

        if args is None:
            return self._deny_with_peek(
                token, tool, {}, ToolTarget(kind="malformed"), now,
                MALFORMED, Kind.MALFORMED_BODY_DENIED,
            )

        if not self._catalog.validate(tool, args):
            return self._deny_with_peek(
                token, tool, args, ToolTarget(kind="malformed"), now,
                MALFORMED, Kind.SCHEMA_INVALID_DENIED,
            )

        try:
            target = self._catalog.describe(tool, args)
        except UnknownTool:
            return self._deny_with_peek(
                token, tool, args, ToolTarget(kind="unknown"), now,
                CAPABILITY, Kind.UNKNOWN_TOOL_DENIED,
            )
        except (ValueError, KeyError, TypeError, IndexError):
            return self._deny_with_peek(
                token, tool, args, ToolTarget(kind="malformed"), now,
                MALFORMED, Kind.DESCRIBE_CLIENT_ERROR_DENIED,
            )
        except Exception as exc:
            return Outcome(kind=Kind.DESCRIBE_BACKEND_FAULT, message=str(exc))

        # Charged BEFORE the decision, because the decision has to price this
        # call against everything else in flight for the same task. What comes
        # back is the state as it was BEFORE this charge -- which is what the
        # policy input and the audit record both carry, and which is why a
        # task's first PII read cannot deny itself under egress.pii_sink.
        charge_id = uuid.uuid4().hex
        try:
            state = self._state.charge(
                token.task_id,
                charge_id=charge_id,
                rows=target.estimated_rows,
                data_class=self._catalog.data_class(tool),
                now=now,
                expires_at=token.exp + self._state_grace,
            )
        except Exception as exc:
            # Nothing has happened, so nothing is recorded -- the same reason
            # DESCRIBE_BACKEND_FAULT records nothing. A store this process
            # cannot reach is not the agent's doing, and this system refuses
            # when it cannot decide.
            return Outcome(
                kind=Kind.STATE_UNAVAILABLE_BEFORE_EXECUTE, message=str(exc)
            )

        decision = self._pdp.decide({
            "principal": {
                "agent_id": token.agent_id,
                "task_id": token.task_id,
                "purpose": token.purpose,
                "allowed_tools": list(token.allowed_tools),
                "counterparties": list(token.counterparties),
            },
            "action": {
                "type": "tool_call",
                "tool": tool,
                "args_digest": args_digest(args),
            },
            "target": target.as_dict(),
            "task_state": state,
        })

        if not decision.allow:
            # Rows AND class: nothing ran and nothing was read, so a refused
            # call must leave no trace in task state.
            self._settle(self._state.release, token.task_id, charge_id, now)
            return self._deny(
                token, tool, args, target, state, decision.rule, Kind.POLICY_DENIED
            )

        try:
            record = self._append(
                token, tool, args_digest(args), target, state, "allow", decision.rule
            )
        except OSError as exc:
            self._settle(self._state.release, token.task_id, charge_id, now)
            return Outcome(kind=Kind.AUDIT_UNAVAILABLE_ON_ALLOW, message=str(exc))

        try:
            result = self._catalog.execute(tool, args)
        except Exception as exc:
            # abandon, not release: the adapter reached the source and may
            # have received bytes before failing. The budget does not pay for
            # a backend outage (A4); the taint is not forgotten because the
            # connection dropped late.
            self._settle(self._state.abandon, token.task_id, charge_id, now)
            return Outcome(
                kind=Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW,
                message=str(exc),
                audit_seq=record["seq"],
            )

        # A negative count is an adapter defect. It costs what was AUTHORISED
        # rather than costing nothing, which is what leaving the state
        # untouched used to mean.
        rejected = result.rows < 0
        rows = target.estimated_rows if rejected else result.rows
        try:
            self._state.reconcile(
                token.task_id, charge_id, rows=rows,
                data_class=result.data_class, now=now,
            )
        except Exception as exc:
            return Outcome(
                kind=Kind.STATE_UNAVAILABLE_AFTER_EXECUTE,
                message=str(exc),
                audit_seq=record["seq"],
            )

        if rejected:
            return Outcome(
                kind=Kind.TAINT_REJECTED_AFTER_EXECUTE,
                message=f"rows must be non-negative, got {result.rows}",
                audit_seq=record["seq"],
            )

        return Outcome(
            kind=Kind.EXECUTED,
            rule=decision.rule,
            result=result,
            audit_seq=record["seq"],
        )
```

Helpers:

```python
    def _settle(self, operation, task_id: str, charge_id: str, now: int) -> None:
        """Release or abandon, swallowing a store failure.

        Deliberately unlike the charge, which refuses. A settle that cannot be
        written leaves a reservation behind, and a reservation's deadline
        already collects one -- so failing the call here would turn a bounded,
        self-healing over-charge into an error the caller cannot act on.
        """
        try:
            operation(task_id, charge_id, now=now)
        except Exception:
            pass

    def _deny_with_peek(self, token, tool, args, target, now, rule, kind) -> Outcome:
        """A denial reached before anything could be charged.

        Reads state at the point of denial rather than up front. There is no
        decision on these paths, only a record, so one peek is the whole of
        it -- and no path in this method reads task state twice.
        """
        try:
            state = self._state.peek(token.task_id, now=now)
        except Exception as exc:
            return Outcome(
                kind=Kind.STATE_UNAVAILABLE_BEFORE_EXECUTE, message=str(exc)
            )
        return self._deny(token, tool, args, target, state, rule, kind)
```

`Spine.task_state` keeps its docstring's argument but now reads
`self._state.peek(task_id, now=self._clock())`.

- [ ] **Step 4: Update the callers**

- `warden/broker/taint.py`: delete `TaintTracker` and `_TaskState`.
- `warden/broker/app.py`: `taint: TaintTracker` → `task_state: TaskStateStore`,
  plus `state_grace_seconds: int = 3600`; pass both to `Spine`.
- `warden/broker/wiring.py`: field `taint` → `task_state`, both kwargs methods.
- `warden/broker/__main__.py`: build
  `InMemoryTaskStateStore(max_in_flight_seconds=config.task_state.max_in_flight_seconds)`
  and pass `state_grace_seconds=config.task_state.ttl_grace_seconds`.
- `warden/broker/proxy.py`: parameter `taint` → `task_state`; line 113 becomes
  `state = task_state.peek(token.task_id, now=int(time.time()))`, with a
  comment: a CONNECT reserves nothing (`estimated_rows` is 0 and there is no
  class to charge), so it reads without creating, and it uses the wall clock
  for the same reason `verifier.verify(token_str)` on the line above does.
- Delete `tests/warden/test_taint.py` (Task 2's file replaces it).
- Update every test constructing `create_app(taint=...)`.

- [ ] **Step 5: Run the full suite**

```bash
.venv/bin/pytest -q 2>&1 | tail -5
ruff check . && .venv/bin/mypy warden/
```

Expected: 722+ collected, all pass, both linters clean.

- [ ] **Step 6: Verify by mutation**

| Mutation | Must turn red |
|---|---|
| `release` → `abandon` on the policy-deny path | `test_a_denied_call_taints_nothing` |
| `abandon` → `release` on the execute-failure path | `test_a_failed_execute_keeps_the_class_and_releases_the_rows` |
| `charge` returns the post-charge view (return `self._view(task)` after inserting) | `test_a_first_pii_read_cannot_deny_itself` |
| Swallow the charge failure and continue with `_empty_state()` | `test_a_store_failure_before_execute_refuses_and_does_not_act` |

Restore each with `git checkout --` and confirm `git status` clean.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: charge the budget before the call, reconcile it after

Replaces the read-then-write TOCTOU with an atomic charge. describe()
prices the call, charge() reserves that price and hands back the state as
it was BEFORE the reservation, OPA judges that with unchanged arithmetic,
and exactly one of reconcile/release/abandon settles it.

The class is charged at the same point and from the same place, because
data_classes_held had the identical hole and it guards R4 egress.pii_sink.
It is monotonic under failure but not under refusal: a denied call leaves
no trace, a failed execute() keeps the class and returns the rows.

Verified by mutation: swapping release for abandon on the deny path,
abandon for release on the failure path, returning the post-charge state
from charge(), and swallowing a charge failure each redden exactly one
test."
```

---

### Task 6: The concurrency test the exit criterion names

§ A's exit criterion asks for "a concurrency test that fires N simultaneous
reads at one `task_id` and asserts the budget is honoured exactly once". Task 2
proved it at the store; this proves it through the whole spine, which is where
it was actually broken.

**Files:**
- Modify: `tests/warden/test_app.py`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

```python
def test_the_row_budget_is_honoured_exactly_once_under_concurrency(tmp_path, signer):
    """The property this whole phase exists for.

    Ten threads read 50 rows each for ONE task against a 50-row budget. The
    PDP stub applies R5's real arithmetic to whatever task_state it is handed,
    and blocks on a barrier first, so every caller is inside the window
    between describe() and decide() at the same time -- the exact window the
    old snapshot-then-record sequence lost updates in.

    Exactly one call may be allowed. Before the charge existed, all ten were.
    """
    threads = 10
    barrier = threading.Barrier(threads)

    def opa_handler(request):
        barrier.wait(timeout=10)
        payload = json.loads(request.content)["input"]
        total = (payload["task_state"]["rows_charged_so_far"]
                 + payload["target"]["estimated_rows"])
        if total > 50:
            return httpx.Response(200, json={
                "result": {"allow": False, "rule": "rows.bounded"}})
        return httpx.Response(200, json={"result": {"allow": True, "rule": "allow"}})

    client, _ = build(tmp_path, signer, None, opa_handler=opa_handler)
    token = token_for(signer, allowed_tools=["read_customers"])
    statuses: list[int] = []
    lock = threading.Lock()

    def call():
        response = client.post(
            "/v1/tools/read_customers/invoke",
            json={"args": {"filter": "all"}},
            headers={"authorization": f"Bearer {token}"},
        )
        with lock:
            statuses.append(response.status_code)

    workers = [threading.Thread(target=call) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert statuses.count(200) == 1, f"expected one allow, got {statuses}"
    assert statuses.count(403) == threads - 1
```

The seeded DB has 120 customers, so an unfiltered `read_customers` estimates
more than 50 rows on its own — seed a 50-row table for this test, or filter to
exactly 50, whichever `build()`'s `seed_customers(db, count=...)` makes
cleanest. Confirm the estimate the adapter actually produces before asserting
on it, rather than assuming.

- [ ] **Step 2: Run it**

```bash
.venv/bin/pytest -q tests/warden/test_app.py -k exactly_once 2>&1 | tail -3
```

Expected: PASS. (It is written after the implementation because it is an
integration proof of Task 5's behaviour, not a driver for new code.)

- [ ] **Step 3: Verify by mutation — the important one**

Make the spine snapshot instead of charge: in `handle_tool_call`, replace the
`self._state.charge(...)` call with `self._state.peek(token.task_id, now=now)`
and settle nothing.

```bash
for i in 1 2 3; do .venv/bin/pytest -q tests/warden/test_app.py -k exactly_once 2>&1 | tail -1; done
```

Expected: FAIL every run, reporting ten 200s. **If it passes even once, the
threads are not actually overlapping** — check that the barrier is inside the
OPA handler and that `TestClient` is not serialising requests; if it is,
drive `spine.handle_tool_call` directly from the threads instead of going
through HTTP.

Restore: `git checkout -- warden/broker/spine.py && git status --short`.

- [ ] **Step 4: Commit**

```bash
git add tests/warden/test_app.py
git commit -m "test: pin the budget exactly once under ten concurrent readers

§A's exit criterion, through the whole spine rather than at the store. The
PDP stub applies R5's real arithmetic and blocks on a barrier, so all ten
callers sit inside the describe-to-decide window together.

Verified by mutation: replacing the charge with a peek makes this report
ten allows on every run, which is what the sequence did before."
```

---

### Task 7: Documentation, and the claims that stop being true

**Files:**
- Modify: `README.md` (the limitations list, the `rows.bounded` row, the
  task-state section around `:251-271`, `:550-552`)
- Modify: `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`
- Modify: `warden/reference/README.md` if it names the field

**Interfaces:**
- Consumes: everything above.
- Produces: nothing.

- [ ] **Step 1: Find every claim the change invalidates**

```bash
grep -rn "rows_returned\|row budget\|only safe with one worker\|Nothing locks it" \
  README.md docs/*.md warden/reference/README.md
.venv/bin/pytest -q tests/test_docs_are_current.py 2>&1 | tail -3
```

- [ ] **Step 2: Rewrite the README's limitation**

The bullet at `README.md:550-552` currently says the row budget is only safe
with one worker because nothing locks it. After this work the accurate
statement is narrower, and it must not overclaim — the store is shared and
atomic, but it is still in-process, so *multiple workers* remain out of reach
until A2. Say exactly that, and say what the number now means:

> **The row budget is charged, not counted.** A call reserves `describe()`'s
> estimate before it runs and reconciles the true count afterwards, so
> concurrent reads for one task cannot both pass the same budget. The store
> is atomic but in-process: two brokers still do not share it, which is A2.

- [ ] **Step 3: Update the ROADMAP**

Mark A1, A3, A4 and A5 done in the § A table, in the style F1/F2/E2 already
use ("**Done** — ..."), and update § A's prose about A3 being "the one to
argue about before building" to point at the spec that argued it. Leave A2 and
A6 open, and leave the `❌ Production` column alone — Phase 3 moves it, not
this.

- [ ] **Step 4: Update ARCHITECTURE and THREAT_MODEL**

`docs/ARCHITECTURE.md`'s per-task-state section gets the charge/reconcile
sequence and the two clocks. `docs/THREAT_MODEL.md:110` currently says every
other control assumes the task state; add what a reservation's deadline means
for that assumption — a broker killed mid-call under-counts nothing, but a
task's budget is briefly stricter than its reads.

- [ ] **Step 5: Run the whole gate one last time**

```bash
ruff check . && .venv/bin/mypy warden/ && .venv/bin/pytest -q 2>&1 | tail -3
opa test warden/policies/ demo/scenario/data.json
```

Expected: clean, 723+ passing (722 baseline, minus `test_taint.py`'s 10, plus
the new store, catalog, config, spine and concurrency tests), `opa test` PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "docs: say what the budget now means, and what still is not true

A1, A3, A4 and A5 are done, so the README's 'nothing locks it' bullet is
replaced -- with a narrower claim, not a stronger one. The store is atomic
and shared within a process; two brokers still do not share it, which is
A2, and the production column does not move until Phase 3."
```

---

## Self-Review

**Spec coverage.** Every section of the spec maps to a task: decision 1 and 2 →
Task 5 (the sequence) with Task 1 supplying the field; decision 3 → Tasks 3 and
5; decision 4 → Task 2; decision 5 → Task 1; decision 6 → Task 5's two `Kind`
members and `_settle`. The interface → Task 2. Expiry and config → Tasks 2 and
4. "How each property is proven" → the mutation tables in Tasks 1, 2, 5 and 6.
"What changes where" → the File Structure table plus Task 7.

**Not covered, deliberately:** A2's Redis store and A6's async spine, both
named as out of scope by the spec.

**Type consistency.** `charge`/`reconcile`/`release`/`abandon`/`peek` carry the
same signatures in Task 2's Interfaces block, the protocol, the implementation
and every call site in Task 5. `task_state` is the keyword everywhere after
Task 5 (`Spine`, `create_app`, `serve_proxy`, `BrokerComponents`);
`state_grace_seconds` is the spine's and `create_app`'s, sourced from
`TaskStateConfig.ttl_grace_seconds`. `rows_charged_so_far` is the only spelling
after Task 1.

**Known ordering risk.** Task 1 regenerates the goldens before the semantics
change lands. That is safe *because* sequential runs are arithmetically
identical under both semantics — Task 5's full-suite run re-verifies the same
goldens, and if they move, the "identical for sequential callers" claim is
wrong and the spec needs revisiting rather than the fixtures.
