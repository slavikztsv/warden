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

    def record_read(self, task_id: str, *, data_class: str | None, rows: int) -> None:
        if rows < 0:
            raise ValueError(f"rows must be non-negative, got {rows}")
        state = self._tasks[task_id]
        if data_class is not None:
            state.data_classes_held.add(data_class)
        state.rows_returned_so_far += rows
