"""The Redis store, against the same contract the in-memory one satisfies.

Two stores that disagree about what a charge means is the failure this file
exists to prevent, so it does not restate the contract -- it RUNS
tests/warden/test_task_state.py's own cases against the other implementation.
A case added there is automatically enforced here.

Skipped without a reachable server, and CI must not be allowed to skip it
silently: .github/workflows/ci.yml asserts the import and the connection
before pytest runs, the same way it guards the mcp extra. A green build over
an unexercised store is exactly the failure that guard exists for.
"""

from __future__ import annotations

import os
import threading
import uuid

import pytest

import tests.warden.test_task_state as contract

redis_lib = pytest.importorskip("redis", reason="requires the warden[redis] extra")

from warden.broker.taint_redis import (  # noqa: E402
    RedisTaskStateStore,
    TaskStateUnavailable,
    connect,
)

URL = os.environ.get("WARDEN_TEST_REDIS_URL", "redis://127.0.0.1:6399/0")


def _client():
    client = connect(URL, socket_timeout_seconds=2)
    try:
        client.ping()
    except Exception as exc:
        pytest.skip(f"no Redis at {URL}: {exc}")
    return client


@pytest.fixture
def store():
    """A store on its own key prefix, so cases cannot see each other's tasks
    without flushing a database the developer may be using for something."""
    return RedisTaskStateStore(
        _client(), max_in_flight_seconds=60, prefix=f"wtest:{uuid.uuid4().hex[:12]}:"
    )


# Every behavioural case from the in-memory suite. Collected by name rather
# than listed, so a case added there cannot quietly fail to run here.
CONTRACT_CASES = sorted(
    name
    for name in dir(contract)
    if name.startswith("test_")
    # Probes InMemoryTaskStateStore._tasks directly; the portable half of it
    # is asserted by test_peek_creates_no_key below.
    and name != "test_peek_does_not_create_an_entry_for_an_unseen_task"
    # Drives a subclass that widens an in-memory read-then-write window. The
    # Redis equivalent is test_concurrent_charges_are_ordered_exactly_once
    # below, whose window is a network round trip and needs no widening.
    and name != "test_concurrent_charges_are_ordered_exactly_once"
)


@pytest.mark.parametrize("case", CONTRACT_CASES)
def test_the_redis_store_satisfies_the_same_contract(case, store, monkeypatch):
    monkeypatch.setattr(contract, "store", lambda: store)
    getattr(contract, case)()


def test_peek_creates_no_key(store):
    """Spine.task_state and proxy.authorize_connect both read through peek
    with an arbitrary id and no minted token behind it -- an operator, a
    diagnostic, a CONNECT probe. A read that planted a key would leak one per
    id ever asked about."""
    assert store.peek("never-seen", now=1000) == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }
    assert store._redis.exists(store._key("never-seen")) == 0


def test_concurrent_charges_are_ordered_exactly_once(store):
    """The property the whole store exists for, over a real server.

    Twenty threads charge 50 rows each against one task; the pre-state each is
    handed must be a distinct multiple of 50, because a lost update is two
    callers seeing the same starting budget. Replacing the single EVAL with a
    peek-then-write hands out 9 distinct values out of 20 -- measured, so this
    assertion is known to have teeth rather than assumed to.
    """
    seen: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20, timeout=30)

    def worker(i: int) -> None:
        barrier.wait()
        pre = store.charge("t", charge_id=f"c{i}", rows=50, data_class="pii",
                           now=1000, expires_at=10**9)
        with lock:
            seen.append(pre["rows_charged_so_far"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(seen) == [50 * i for i in range(20)]
    assert store.peek("t", now=1000)["rows_charged_so_far"] == 1000


def test_two_brokers_share_one_budget():
    """§A's headline claim, and the whole reason this store exists.

    Two INDEPENDENT clients -- what two broker processes have -- charging the
    same task concurrently. The budget is one budget: each caller is handed a
    distinct multiple of ten, and the total is what all ten committed to.
    Pointing the two at different databases is what must break it.
    """
    prefix = f"wtest:{uuid.uuid4().hex[:12]}:"
    first = RedisTaskStateStore(_client(), prefix=prefix)
    second = RedisTaskStateStore(_client(), prefix=prefix)

    seen: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(10, timeout=30)

    def worker(i: int) -> None:
        broker = first if i % 2 == 0 else second
        barrier.wait()
        pre = broker.charge("t", charge_id=f"c{i}", rows=10, data_class="pii",
                            now=1000, expires_at=10**9)
        with lock:
            seen.append(pre["rows_charged_so_far"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(seen) == [10 * i for i in range(10)]
    assert first.peek("t", now=1000)["rows_charged_so_far"] == 100
    assert second.peek("t", now=1000)["rows_charged_so_far"] == 100


def test_an_unreachable_store_raises_an_oserror():
    """TaskStateUnavailable derives from OSError so broker/proxy.py's existing
    ladder catches it in the branch that RECORDS the refusal. redis-py's own
    TimeoutError does not -- without the translation an outage would be
    answered with a bare 403 and no audit record at all."""
    store = RedisTaskStateStore(
        connect("redis://127.0.0.1:6398/0", socket_timeout_seconds=1)
    )
    with pytest.raises(TaskStateUnavailable) as caught:
        store.peek("t", now=1000)
    assert isinstance(caught.value, OSError)


def test_retries_are_off_and_the_timeout_is_bounded():
    """Both redis-py defaults are wrong here and both were measured (6.4.0:
    Retry(retries=3), socket_timeout=None). A retried charge hits the
    duplicate-charge_id guard -- the case where the script already ran -- and
    a retried reconcile commits its rows again. A hung server with no timeout
    would pin one of the broker's 16 shared worker threads forever."""
    kwargs = connect(URL, socket_timeout_seconds=2).connection_pool.connection_kwargs
    assert kwargs["socket_timeout"] == 2
    assert kwargs["retry"]._retries == 0
