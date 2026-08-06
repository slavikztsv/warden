"""The store's contract: what a charge is, and what settles it."""

from __future__ import annotations

import threading
import time

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
    """Load-bearing: a view including the caller's own class would make a
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
    """describe() and execute() open separate connections, so the table can
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
    s.abandon("4711", "c1", data_class="pii", now=1000)
    assert s.peek("4711", now=1000) == {
        "data_classes_held": ["pii"], "rows_charged_so_far": 0,
    }


def test_release_keeps_a_class_an_earlier_settled_call_committed():
    """Release drops what THIS charge added, not what the task already held.
    A task that has genuinely read PII stays tainted through a later refusal."""
    s = store()
    charge(s, cid="c1", rows=1, data_class="pii")
    s.reconcile("4711", "c1", rows=1, data_class="pii", now=1000)
    charge(s, cid="c2", rows=1, data_class="pii", now=1000)
    s.release("4711", "c2", now=1000)
    assert s.peek("4711", now=1000)["data_classes_held"] == ["pii"]


def test_release_drops_a_class_no_settled_call_ever_committed():
    s = store()
    charge(s, cid="c1", rows=1, data_class="internal")
    s.reconcile("4711", "c1", rows=1, data_class="internal", now=1000)
    charge(s, cid="c2", rows=1, data_class="pii", now=1000)
    s.release("4711", "c2", now=1000)
    assert s.peek("4711", now=1000)["data_classes_held"] == ["internal"]


def test_a_leaked_reservation_expires():
    s = store()
    charge(s, cid="c1", rows=50, now=1000)
    assert s.peek("4711", now=1059)["rows_charged_so_far"] == 50
    assert s.peek("4711", now=1061)["rows_charged_so_far"] == 0


def test_reconciling_past_the_deadline_still_charges_the_rows():
    """A settle that raced its own deadline must not raise -- the action it
    reports has already happened -- and must still charge what was read.

    The deadline collects a LEAK; it is not an amnesty. A call slow enough to
    outlive max_in_flight_seconds really did return those rows, and dropping
    them because the reservation was collected first would under-count the
    budget, which is the one direction that fails open.
    """
    s = store()
    charge(s, cid="c1", rows=50, now=1000)
    s.reconcile("4711", "c1", rows=50, data_class="pii", now=1_000_000)
    assert s.peek("4711", now=1_000_000) == {
        "data_classes_held": ["pii"], "rows_charged_so_far": 50,
    }


def test_abandoning_past_the_deadline_still_taints_the_task():
    """The taint must not depend on the reservation still being there.

    A hung backend is both the likeliest cause of an execute() failure and
    the likeliest way to outlive max_in_flight_seconds, so reading the class
    off the reservation alone would drop the taint in exactly the case it
    matters most. abandon() takes the class explicitly for that reason.
    """
    s = store()
    charge(s, cid="c1", rows=50, data_class="pii", now=1000)
    s.abandon("4711", "c1", data_class="pii", now=1_000_000)
    assert s.peek("4711", now=1_000_000) == {
        "data_classes_held": ["pii"], "rows_charged_so_far": 0,
    }


def test_releasing_past_the_deadline_is_a_no_op():
    """Release after collection has nothing to give back, and must not raise
    or go negative."""
    s = store()
    charge(s, cid="c1", rows=50, now=1000)
    s.release("4711", "c1", now=1_000_000)
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


def test_charging_an_expired_task_starts_it_clean():
    """Eviction is a reset, not a carry-forward: a task whose state expired
    must not have its old committed rows resurrected by the next charge."""
    s = store()
    s.charge("4711", charge_id="c1", rows=40, data_class="pii", now=1000,
             expires_at=2000)
    s.reconcile("4711", "c1", rows=40, data_class="pii", now=1000)
    pre = s.charge("4711", charge_id="c2", rows=1, data_class=None, now=3000,
                   expires_at=4000)
    assert pre == {"data_classes_held": [], "rows_charged_so_far": 0}


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


def test_a_rejected_reconcile_leaves_the_reservation_to_settle():
    """The spine reconciles at the estimate after a rejection, so the
    reservation must still be there to settle."""
    s = store()
    charge(s, cid="c1", rows=7)
    with pytest.raises(ValueError):
        s.reconcile("4711", "c1", rows=-5, data_class=None, now=1000)
    s.reconcile("4711", "c1", rows=7, data_class=None, now=1000)
    assert s.peek("4711", now=1000)["rows_charged_so_far"] == 7


def test_a_duplicate_charge_id_is_rejected():
    s = store()
    charge(s, cid="c1", rows=1)
    with pytest.raises(ValueError):
        charge(s, cid="c1", rows=1)


class WideWindowStore(InMemoryTaskStateStore):
    """The store, with the read-then-write window inside charge() widened.

    Necessary, and the necessity was measured rather than assumed. The first
    version of the test below drove the plain store from twenty threads and
    passed with the lock REMOVED, on five runs out of five: under the GIL the
    gap between reading the pre-state and inserting the reservation is a few
    bytecodes, so the interleaving it was supposed to catch essentially never
    happened. A concurrency test that cannot fail without its lock is not
    evidence of anything.

    The sleep is a scheduling nudge, not a timing assertion -- nothing below
    asserts on elapsed time, only on values -- and it sits inside the region
    the lock is supposed to protect. With the lock, callers serialise through
    it and each is handed a distinct pre-state. Without it, they overlap and
    read the same one, which is exactly the TOCTOU this store replaces.
    """

    def _view(self, task, *, now=None):  # type: ignore[override]
        time.sleep(0.002)
        return InMemoryTaskStateStore._view(task, now=now)


def test_concurrent_charges_are_ordered_exactly_once():
    """The property the whole store exists for. Twenty threads charge 50 rows
    each against one task; the pre-state each is handed must be a distinct
    multiple of 50, because a lost update is two callers seeing the same
    starting budget -- which is the TOCTOU this replaces."""
    s = WideWindowStore(max_in_flight_seconds=60)
    seen: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker(i: int) -> None:
        barrier.wait(timeout=10)
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
