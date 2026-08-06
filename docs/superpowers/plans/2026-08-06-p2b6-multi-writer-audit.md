# P2·B6 — multi-writer audit sequencing: implementation plan

**Design:** [2026-08-06-p2b6-multi-writer-audit-design.md](../specs/2026-08-06-p2b6-multi-writer-audit-design.md)
**Blast radius:** one module — `warden/broker/audit.py`. No interface changes,
so no call site moves and no wrapper needs to grow a method.

Written expecting the *plan* to be wrong rather than the implementation. Where
this document states a number or a behaviour, it came from a spike run, not
from reasoning.

---

## Step 1 — `audit.py`: replace the cached head with a locked tail read

`AuditLog.append` becomes:

```
with self._lock:                      # in-process, cheap (decision 7)
    with self.path.open("a+b") as handle:      # Path.open: the failed-write test patches it
        _acquire(handle, self._lock_timeout)   # LOCK_NB spin to a deadline (decision 4)
        seq, prev_hash = _head_from_tail(handle)   # adaptive window (decisions 1, 3)
        ...build body, hash, write, flush...
```

New module-level helpers, both private:

- `_acquire(handle, timeout)` — `fcntl.flock(fd, LOCK_EX | LOCK_NB)` in a loop
  against a `time.monotonic()` deadline, 5 ms poll, raising `OSError` on
  expiry. **Not** `SIGALRM`, **not** unbounded.
- `_head_from_tail(handle)` — `fstat` for the size; `(0, GENESIS_HASH)` if
  empty; otherwise read a window from the end, `rstrip(b"\n")`, `rfind(b"\n")`,
  double the window and retry while no boundary is found and the start of the
  file has not been reached. Wrap `json.JSONDecodeError` / `KeyError` as
  `OSError` so a torn tail refuses the append instead of escaping the spine's
  handlers (decisions 4, 5).

Deletions: `self._head_cache`, `_head()`. `records()` and `verify_chain()` are
untouched. `__init__` still reads nothing — the reason B1 populated lazily
(`warden verify-chain` must be pointable at a corrupt log) is now satisfied by
construction, and that comment moves rather than disappearing.

`_LOCK_TIMEOUT_SECONDS = 5.0` as a constructor default, not a config knob. It
becomes one when B2 adds `[audit].durability`, so the config surface changes
once rather than twice — recorded because A6's `worker_threads` argument
(an operational limit does not get to be undocumented) points the other way,
and the difference is that this one is a fixed documented constant in a single
place rather than a machine-dependent `min(32, cpu_count + 4)`.

Byte-for-byte identical output: `json.dumps(record, sort_keys=True) + "\n"`,
encoded UTF-8. The golden chain must still verify.

## Step 2 — tests, each written to fail first

New, in `tests/warden/test_audit.py`:

1. **`test_two_processes_appending_produce_one_intact_chain`** — the load-bearing
   one. `multiprocessing` (not threads: threads are already covered by the
   `threading.Lock`, and would pass against the broken code). N processes ×
   M appends, then assert dense seqs `1..N*M` and `verify_chain() == (True, None)`.
2. **`test_a_record_wider_than_the_tail_window_is_still_found`** — a `target`
   host of 20 000 characters, then a further append that must chain onto it.
3. **`test_a_torn_trailing_line_refuses_the_append`** — write a partial line,
   assert `OSError`, assert the file was not repaired.
4. **`test_a_held_lock_times_out_as_an_oserror`** — a subprocess holds the
   `flock`; assert `OSError` within a short configured timeout rather than a hang.
5. **`test_the_head_is_read_from_the_file_not_from_memory`** — two `AuditLog`
   objects on one path, alternating appends, chain intact. This is the one that
   fails if a cache is ever reinstated.

Edited: `test_appending_does_not_re_read_the_log` (strengthen — the first
append no longer gets an exemption) and
`test_a_failed_write_does_not_advance_the_cached_head` (rename to what it now
proves: a failed write consumes no sequence number).

## Step 3 — verify by mutation

Ten rows in the spec's proof table. Each is broken, run, seen **red**,
restored, run, seen **green**. Commit *before* mutating; clear `__pycache__`
after every revert (whole-second mtime + equal size reruns the mutant).

## Step 4 — move the claims with the code

The one-worker limitation is stated in four places and all four are now wrong
in the same specific way — the audit chain is no longer the reason:

- `README.md` — "Known limitations" and the "what it does not do" line
- `docs/DEPLOYMENT.md` — "Run the broker with one worker"
- `docs/ARCHITECTURE.md` — the Distributed row
- `docs/ROADMAP.md` — B6's row, and § B's exit

Each must say what is now true and what is *still* not: the chain admits a
second writer on one host; `flock` is per-kernel so a shared network filesystem
is not covered; and one worker remains the supported deployment because the
**process model** does not exist, not because of the log. Understating the
product is as wrong as overstating it — E2 sat wrong for four commits that way.

## Step 5 — all five gates, then commit

```
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy warden --ignore-missing-imports
opa test warden/policies/ demo/scenario/data.json
.venv/bin/warden-demo explain --quiet-why      # still 7 records, 3 refusals, 1 record read
```

The demo count is a *regression* check here, not a new expectation: this change
is invisible to a single writer, so any movement in it means the record body
changed.
