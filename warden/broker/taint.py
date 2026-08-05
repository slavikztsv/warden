"""Per-task data-flow state.

Taint is tracked at TASK granularity, not per string. Tracking strings would
mean summarizing or re-encoding the data launders it; a task that has touched
a PII source carries that class until the task ends.

This state lives in the enforcement point rather than in policy, which keeps
OPA a pure decision function.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _TaskState:
    data_classes_held: set[str] = field(default_factory=set)
    rows_returned_so_far: int = 0


class TaintTracker:
    def __init__(self) -> None:
        self._tasks: dict[str, _TaskState] = defaultdict(_TaskState)

    def snapshot(self, task_id: str) -> dict:
        state = self._tasks[task_id]
        return {
            "data_classes_held": sorted(state.data_classes_held),
            "rows_returned_so_far": state.rows_returned_so_far,
        }

    def peek(self, task_id: str) -> dict:
        """The same view as `snapshot`, WITHOUT creating an entry for a
        task_id that has never read anything.

        `snapshot` and `record_read` both key off `self._tasks[task_id]`, a
        defaultdict -- fine for every caller on the serving path, which only
        ever asks about a task_id a minted token names, about to spend its
        budget, and which `record_read` (or the next `snapshot`) will fill
        in regardless. A read-only caller -- a diagnostic, an operator
        question -- may ask about an ARBITRARY string with no minted token
        behind it at all, and creating a phantom entry for one that never
        spends anything would leak memory for every id it is ever asked
        about, forever. `Spine.task_state` reads through here, not through
        `snapshot`, for exactly that reason.
        """
        state = self._tasks.get(task_id)
        if state is None:
            return {"data_classes_held": [], "rows_returned_so_far": 0}
        return {
            "data_classes_held": sorted(state.data_classes_held),
            "rows_returned_so_far": state.rows_returned_so_far,
        }

    def record_read(self, task_id: str, *, data_class: str | None, rows: int) -> None:
        if rows < 0:
            raise ValueError(f"rows must be non-negative, got {rows}")
        state = self._tasks[task_id]
        if data_class is not None:
            state.data_classes_held.add(data_class)
        state.rows_returned_so_far += rows
