"""What a record's fields mean, for every process that writes one.

Two processes write to one audit log: the broker, through
[spine.py](spine.py), and the control plane, through [control.py](control.py).
They must agree on what a field's value means or the chain is one file
containing two vocabularies.

These two functions used to live in spine.py, which is where the broker
needed them. Importing them from there is what the control plane cannot
afford: measured, the `broker-control` process's warden import graph goes
from 7 modules to 13 the moment it reaches spine.py, because spine pulls in
warden.broker.taint and warden.broker.adapters.base -- the whole enforcement
stack, loaded into the one process that holds the private signing key, whose
own module docstring is entirely about staying minimal. Nothing here imports
anything but the standard library, and the graph stays at 9 -- this module and
the log it writes into.

Duplicating them instead was the other option, and it loses to a live
precedent: A2 changed what task state contains, this quarter. A second copy
of that shape would have been the copy that did not change.
"""

from __future__ import annotations

import hashlib
import json


def args_digest(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def empty_task_state() -> dict:
    """A task that has held nothing and charged nothing.

    A fresh dict per call, deliberately -- not a shared module-level
    constant. AuditLog.append does `record = dict(body)`, a SHALLOW copy,
    so a record built from one shared mutable dict would let every
    unauthenticated refusal's stored task_state alias the same object.
    Nothing aliases it today because spine's `_refuse()` discards the record
    it gets back, but the next caller to keep that return value would not
    know it was holding a landmine. That warning gets more load-bearing with
    a second caller, not less.

    The two callers mean two different things by it, and only one of them is
    a measurement:

      * spine.py writes it for a caller with NO AUTHORITY AT ALL -- there is
        no task, so there is nothing to have held.
      * control.py writes it for a mint, where it is the MINTER'S VIEW and
        not the task's. Task state is keyed by task_id and deliberately
        survives token renewal (see taint.py), so a renewal minted against a
        task that already holds `pii` and has charged 5001 rows still
        records [] and 0. The control plane holds no task-state store; this
        is what it can honestly say, not what is true of the task. See the
        B7 design's decision 6.
    """
    return {"data_classes_held": [], "rows_charged_so_far": 0}
