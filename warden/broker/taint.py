"""Per-task state: the row budget, and the data classes held.

Taint is tracked at TASK granularity, not per string. Tracking strings would
mean summarizing or re-encoding the data launders it; a task that has touched
a PII source carries that class until the task ends.

This state lives in the enforcement point rather than in policy, which keeps
OPA a pure decision function.

Both halves are CHARGED rather than counted, and that is the change P2·A
made. A call is priced by describe(), charged before it runs, and its
reservation is swapped for the truth when it returns -- so
`rows_charged_so_far` means "rows this task has committed to reading,
settled or in flight", and a class a call is about to produce is visible to
a concurrent caller rather than only after the read finishes. Without that,
N concurrent 50-row reads all pass a 50-row budget, and an egress running
alongside a PII read sees a task that holds nothing.

The strictness is the control. A reserved-but-unused row counts against the
task until reconciliation, deliberately.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Protocol


class TaskStateUnavailable(OSError):
    """The store could not be reached.

    Part of the INTERFACE, not of any one implementation, which is why it
    lives here beside the Protocol rather than in the Redis module. A second
    implementation must not have to invent its own.

    Derives from OSError deliberately. `redis.exceptions.TimeoutError` does
    not -- verified -- so without this an outage would fall through
    broker/proxy.py's `except OSError` into its `except Exception`, and be
    answered with a bare 403 in the one component whose stated reason for
    existing is that denying without recording is the failure mode it cannot
    have.

    The in-memory store never raises it: a dict cannot be unreachable.
    """


@dataclass
class _Reservation:
    """One call's charge, in flight.

    Carries its own data class, which is what makes release() correct by
    construction rather than by bookkeeping: dropping the reservation drops
    the class it claimed, and cannot touch a class any settled call
    committed. The first attempt at this held one class set per task and
    tried to work out on release which members were "only claimed" -- that
    reasoning is wrong for a zero-row read, because a mail send legitimately
    commits a class while committing no rows.

    The deadline is absolute rather than a duration, so pruning is a
    comparison against the caller's `now` and never a read of a clock this
    module does not own.
    """

    rows: int
    deadline: int
    data_class: str | None = None


@dataclass
class _Task:
    # Classes put here by a call that SETTLED -- reconciled or abandoned.
    # A class merely claimed by a charge still in flight lives on that
    # reservation, and the view unions the two.
    committed_classes: set[str] = field(default_factory=set)
    rows_committed: int = 0
    reservations: dict[str, _Reservation] = field(default_factory=dict)
    expires_at: int = 0


class TaskStateStore(Protocol):
    """What the spine needs from task state, and nothing more.

    Every method takes `now`, and `charge` takes the `charge_id` too, from the
    caller rather than reading a clock or generating an id itself. That is not
    fastidiousness: a Redis implementation runs this logic inside a Lua
    script, and Redis requires scripts to be deterministic, so neither a
    clock read nor uuid4() is available inside one. Passing both in keeps one
    interface honest to both implementations -- and, incidentally, lets every
    expiry test run without a sleep.

    One charge has exactly three possible endings, and they are separate
    methods rather than one `settle(keep_class=...)` because the fail-closed
    direction differs between them. That asymmetry is the thing a reader most
    needs to see, not the thing to hide behind a flag.
    """

    def charge(self, task_id: str, *, charge_id: str, rows: int,
               data_class: str | None, now: int, expires_at: int) -> dict: ...

    def reconcile(self, task_id: str, charge_id: str, *, rows: int,
                  data_class: str | None, now: int) -> None: ...

    def release(self, task_id: str, charge_id: str, *, now: int) -> None: ...

    def abandon(self, task_id: str, charge_id: str, *,
                data_class: str | None, now: int) -> None: ...

    def peek(self, task_id: str, *, now: int) -> dict: ...


class InMemoryTaskStateStore:
    """The single-process store. One lock, held for the whole of every
    operation.

    That lock is what replaces the accident which used to make this safe.
    Spine.handle_tool_call contained no `await` and every collaborator it
    called blocked, so the broker served one tool call at a time and a
    read-then-write could not interleave. That was a property of the call
    graph rather than of the state, and both A6 and a second worker dissolve
    it. Nothing here depends on it.

    The budget this holds is `committed + Σ(live reservations)`: rows a task
    has committed to reading, whether or not they have arrived yet. A call is
    priced by describe(), charged before it runs, and its reservation is
    swapped for the true count when it returns.
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
        """Reserve this call's price, and return the state as it was BEFORE
        the reservation.

        Returning the pre-state is load-bearing, not a convenience. It is what
        the policy input and the audit record both carry, and it is why a
        task's first PII read cannot deny itself: a view that already included
        this call's own class would trip egress.pii_sink on the very read that
        produced it.
        """
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
                rows=max(rows, 0),
                deadline=now + self._max_in_flight,
                data_class=data_class,
            )
            # Never shortens: task state deliberately outlives one token, so a
            # short-lived renewal must not truncate what a longer one set.
            task.expires_at = max(task.expires_at, expires_at)
            return before

    def reconcile(self, task_id: str, charge_id: str, *, rows: int,
                  data_class: str | None, now: int) -> None:
        """The call succeeded: commit the true row count, keep the class."""
        if rows < 0:
            # Raised BEFORE the reservation is touched, so the caller can
            # settle it at the estimate instead. A reconcile that both
            # mutated and raised would leave no defined state to recover to.
            raise ValueError(f"rows must be non-negative, got {rows}")
        with self._lock:
            task, reservation = self._settle(task_id, charge_id, now)
            if task is None:
                return
            task.rows_committed += rows
            self._commit_class(task, reservation)
            # Unioned from the RESULT as well as from the reservation.
            # Redundant today, because every adapter derives
            # ToolResult.data_class and its binding class from the same value;
            # it keeps a future adapter that discovers a class at execute time
            # from silently losing it.
            if data_class is not None:
                task.committed_classes.add(data_class)

    def release(self, task_id: str, charge_id: str, *, now: int) -> None:
        """Nothing ran: drop the rows AND the class.

        A refused call must leave no trace in task state. Keeping the class
        here would let one denied PII read poison a task for the rest of its
        life, which an agent could trip deliberately.

        There is no bookkeeping to do: the class lived on the reservation, so
        dropping the reservation drops it, and a class some settled call
        committed is untouched because it was never stored here.
        """
        with self._lock:
            self._settle(task_id, charge_id, now)

    def abandon(self, task_id: str, charge_id: str, *,
                data_class: str | None, now: int) -> None:
        """execute() ran and failed: drop the rows, KEEP the class.

        The opposite of release() in exactly one respect, and each direction
        is the fail-closed one. The adapter reached the source and may have
        received bytes before failing, so the taint stands; the budget does
        not pay for a backend outage, so the rows go back.

        Takes the class explicitly, like reconcile() and unlike release(),
        so a call slow enough to outlive its own deadline still taints the
        task. Relying on the reservation alone would silently drop the taint
        in exactly the case -- a hung backend -- where a failure is most
        likely.
        """
        with self._lock:
            task, reservation = self._settle(task_id, charge_id, now)
            if task is None:
                return
            self._commit_class(task, reservation)
            if data_class is not None:
                task.committed_classes.add(data_class)

    def peek(self, task_id: str, *, now: int) -> dict:
        """The same view charge() returns, WITHOUT creating an entry for a
        task_id that has never spent anything.

        Spine.task_state and proxy.authorize_connect both read through here,
        and either may be handed an arbitrary string with no minted token
        behind it -- a diagnostic, an operator question, a CONNECT probe.
        Creating a phantom entry for every id ever asked about would leak one
        per id, forever.
        """
        with self._lock:
            task = self._live(task_id, now)
            if task is None:
                return {"data_classes_held": [], "rows_charged_so_far": 0}
            return self._view(task, now=now)

    def _live(self, task_id: str, now: int) -> _Task | None:
        """The task, or None if it never existed or has expired.

        Expiry is checked here rather than left to the sweep, so correctness
        never depends on when the sweep last ran -- and so an expired task's
        committed rows can never be resurrected by the next charge.
        """
        task = self._tasks.get(task_id)
        if task is None:
            return None
        if task.expires_at <= now:
            del self._tasks[task_id]
            return None
        return task

    def _sweep(self, now: int) -> None:
        """Drop every expired task, at most once per interval.

        A Redis store gets this free from key TTLs; an in-process dict has to
        do it itself, and doing it on every request would make each call O(live
        tasks). _live() above is what makes this an optimisation rather than a
        correctness mechanism.
        """
        if now < self._next_sweep:
            return
        self._next_sweep = now + self._sweep_interval
        for task_id in [t for t, s in self._tasks.items() if s.expires_at <= now]:
            del self._tasks[task_id]

    def _settle(
        self, task_id: str, charge_id: str, now: int
    ) -> tuple[_Task | None, _Reservation | None]:
        task = self._live(task_id, now)
        if task is None:
            return None, None
        self._prune(task, now)
        # Absent is not an error: the deadline may have collected this
        # reservation first, and a settle that raced its own expiry must not
        # take the call down after the action has already happened. The class
        # is lost with it -- bounded by max_in_flight_seconds, and the
        # alternative is holding a taint for a call nobody can account for.
        return task, task.reservations.pop(charge_id, None)

    @staticmethod
    def _commit_class(task: _Task, reservation: _Reservation | None) -> None:
        """Move a settled reservation's class onto the task.

        Called by reconcile() and abandon(), never by release(): those two
        mean the adapter reached the source, and this one means it did not.
        """
        if reservation is not None and reservation.data_class is not None:
            task.committed_classes.add(reservation.data_class)

    @staticmethod
    def _prune(task: _Task, now: int) -> None:
        for charge_id in [c for c, r in task.reservations.items() if r.deadline <= now]:
            del task.reservations[charge_id]

    @staticmethod
    def _view(task: _Task, *, now: int | None = None) -> dict:
        """Committed plus in flight, for both halves of the state.

        `now` is passed only by peek(), which must not mutate: it filters
        expired reservations out of the answer without deleting them. Every
        other caller has already pruned under the lock.
        """
        reservations = list(task.reservations.values())
        if now is not None:
            reservations = [r for r in reservations if r.deadline > now]
        claimed = {r.data_class for r in reservations if r.data_class is not None}
        return {
            "data_classes_held": sorted(task.committed_classes | claimed),
            "rows_charged_so_far": task.rows_committed
            + sum(r.rows for r in reservations),
        }
