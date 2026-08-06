# P2·B2 — audit durability: making `append()` mean what the README says

**Status:** approved design, measured before it was written. Adversarially
reviewed after the first draft — see *What the review changed*.
**Sequenced by:** [docs/ROADMAP.md](../../ROADMAP.md) § B, item B2 — "`os.fsync`
before returning from `append()`, with the durability level configurable and
the default being the safe one". Size S.
**Covers:** B2 only, in one commit.
**Deliberately does not cover:** B3 (rotation), B4, B5 (the cross-host case and
the pluggable sink), C2, and the process model — and therefore § A's exit
criterion, which still has nothing to start a second worker with. See *What
this does not do*.
**Verified against:** CPython 3.12 on ext4 under WSL2. Every number below was
measured through the real `append()` path, not estimated: the 16× cost, the
`fdatasync`/`fsync` equivalence that kills a third level, the directory fsync,
the demo's total, the import graph (9 modules before, 9 after) and the suite's
own append count (308 across 837 tests in 13.8 s, so the safe default costs the
suite ~0.5 s — which is why the tests do **not** get a weaker default than the
product). Four of them changed a decision.

---

## What this is

`README.md:167` states the step that the whole design turns on:

> | **record** | Write the decision down, **before** anything happens. | `503`, and nothing runs |

`append()` writes the line and calls `handle.flush()`. `flush()` copies the
bytes from a userspace buffer into the kernel's page cache. It does not put
them on a disk. So the record survives the broker being killed, and does not
survive the host losing power — and a host that loses power between the record
and the action loses **exactly the record whose action went ahead**. The log
under-reports in the one direction an audit log may not under-report in.

`docs/ROADMAP.md:120-123` already says so, in the sentence this work exists to
delete:

> Separately, `append()` calls `handle.flush()` with no `os.fsync()` — so "the
> decision is written down **before** anything happens", the property the whole
> design turns on, is durable against a process crash but not against a host
> loss. **The claim is stronger than the code.**

That is the entire item. B2 is not a new promise; it is the deletion of a
caveat. **The documentation change B2 makes is a subtraction.** `README.md`
needs no new sentence, because its claim was already unqualified — it was
simply not true yet.

---

## What the review changed

The first draft of this document was reviewed against the code before any of
it was implemented, because *the plan is wrong and the implementation is not*
is this project's recorded failure mode. Four things changed.

1. **The paragraph B2 rewrites contains a claim B6 already falsified.**
   `ROADMAP.md:123-124` still reads "Its `threading.Lock` is also process-local,
   so a second worker breaks the chain rather than slowing it." B6 replaced that
   lock's role with an `flock` on the log file and measured the fix; the
   sentence survived because B6 rewrote the *table row* and not this paragraph.
   It is stale, it is in the exact four lines B2 must rewrite, and leaving it
   there while deleting the sentence next to it would produce a paragraph half
   of which is current. Folded into *What changes*. This is a defect in the
   existing docs, not in B2's plan, and it is recorded here because the way it
   was found — rewriting a paragraph forces you to read all of it — is worth
   repeating.

2. **A third durability level was in the first draft and is measured out of
   it.** `fdatasync` skips the metadata flush and is the usual "cheaper fsync".
   An append **changes the file size**, which is metadata `fdatasync` must
   flush anyway, so on this filesystem the two are indistinguishable: 1687 µs
   against 1649 µs, inside the noise. A level that buys nothing measurable is a
   config value someone has to choose between. Two levels.

3. **"Configurable in both TOMLs" was justified by the wrong precedent.** The
   draft reasoned by analogy to `[audit].path` and `[tokens].issuer` — two-place
   values that *must* agree, documented with matching comments and a
   shipped-pair test. `durability` is not that shape. A broker at `"flush"` and
   a control plane at `"fsync"` is a **coherent deployment**: the grant must
   survive power loss, the high-volume decisions accept the risk. So the
   comments say the values need not agree, and there is deliberately **no**
   shipped-pair equality test — one would assert a constraint that does not
   exist. See decision 2.

4. **The first record's durability was missing entirely.** `fsync` on the file
   descriptor makes the file's *contents* durable. It does not make the
   **directory entry** durable, so a power loss shortly after a log is first
   created can lose the entire file, including record 1, whose `append()`
   already returned and whose action therefore went ahead. A durability feature
   with a hole at record 1 is a fresh instance of "the claim is stronger than
   the code" — the sentence B2 exists to delete. See decision 5.

5. **`durability` has to be a *public* attribute, and the draft made it
   private.** Proof-table row 13 pins the config → constructor wiring on the
   broker side, and the only non-mocking way to do that is
   `broker_main.build(config)` → `components.audit.durability`. `self.path` is
   already public on `AuditLog` for the same kind of reason. A `_durability`
   would have forced row 13 into a mock and made the test about the call rather
   than the result.

6. **The two construction sites are not symmetric, and the draft assumed they
   were.** `broker_main.build()` returns `(app, components)`, so the broker's
   `AuditLog` is reachable. `control_main.build()` returns **only the app** —
   the log is a closure argument to `create_control_app` and nothing exposes
   it. Row 14 therefore needs a capturing `AuditLog` subclass patched into
   `control_main`, and that is named here rather than left for the implementer
   to discover mid-task.

7. **Four things the draft asserted are now checked rather than assumed.**
   `BrokerConfig` and `ControlConfig` really are constructed *only* in
   `loader.py` — `test_key_split.py`'s `broker_config`/`control_config` helpers
   go through `load_*_config`, and `test_mcp_surface.py:694`'s
   `dataclasses.replace` works fine against required fields — so field
   placement is free and neither dataclass needs a default. `spine.py` catches
   `OSError` around *every* `_append` call site (lines 339, 489, 514, 563) and
   `control.py:178` catches it around `record_mint`, so decision 6 adds nothing.
   `NarratedAudit` forwards `path` explicitly and nothing reads `.durability`
   through it, so the wrapper cannot rot against this change — the
   `warden-demo explain` gate proves it. And **no record count anywhere
   changes**, so B7's "four sevens" class of trap does not apply to this work at
   all.

---

## What it costs

Measured through the real `append()` path, at B6's own benchmark points, 200
samples each after a 20-append warmup:

| existing records | flush only (today) | with `fsync` | ratio |
|---|---|---|---|
| 100 | med 107 µs, p95 198 µs | med 1737 µs, p95 2614 µs | 16.2× |
| 1000 | med 106 µs, p95 147 µs | med 1905 µs, p95 2603 µs | 17.9× |
| 4000 | med 109 µs, p95 174 µs | med 1713 µs, p95 2373 µs | 15.7× |

**Flat in log size**, exactly as B6's tail read is — the cost is one syscall's
round trip to the device, not a function of what is already in the file.

The syscalls in isolation, on one open handle, 300 samples:

| | median |
|---|---|
| `write` + `flush` | 1.4 µs |
| `write` + `flush` + `fdatasync` | 1624 µs |
| `write` + `flush` + `fsync` | 1622 µs |
| `open` + `fsync` + `close` on the parent **directory** | 1435 µs |

Two things follow. `fdatasync` is not a cheaper option here (decision 1), and
the durable write is **~1000× the flush** — the append's other ~105 µs of
Python, JSON and hashing is now noise.

What it costs the things this repo runs:

- **The demo's 8-record run: 0.87 ms → 16.3 ms.** Invisible inside a `warden-demo
  explain` that takes seconds and a `--matrix` that takes about a minute.
- **The deployment's audit ceiling: ~9,300 → ~590 records/second.** Appends
  serialize under the `flock`, so this is a whole-deployment number, not a
  per-thread one, and it is the honest headline. It is stated in
  `docs/DEPLOYMENT.md` rather than left to be discovered.
- **`[broker].worker_threads = 16`** still buys 16-way concurrency for
  everything *except* the append, which was already serialized. The queue
  behind it is now ~16× longer: sixteen threads all recording at once make the
  last one wait ~27 ms, against ~1.7 ms before. Far inside the 5 s
  `_LOCK_TIMEOUT_SECONDS`, which is why that constant does not move
  (decision 8).

**These numbers are WSL2-on-a-virtual-disk numbers.** A production ext4 on NVMe
will be faster and a network filesystem slower. The transferable part is the
**ratio** and the shape (flat in log size), not the absolute microseconds.

---

## The ten decisions

### 1 · `[audit].durability`, two levels, `"fsync"` by default

```toml
[audit]
path       = "/data/audit.jsonl"
durability = "fsync"   # or "flush"
```

- `"fsync"` — the record is on stable storage before `append()` returns.
  Survives host power loss. **The default**, because ROADMAP B2 says the
  default must be the safe one, and because the alternative silently weakens
  every config written before this key existed.
- `"flush"` — the record is in the kernel page cache before `append()` returns.
  Survives a process crash, not a host loss. This is today's behaviour, kept
  reachable and named.

The levels are named for the **syscall**, not for a promise (`"strict"` /
`"relaxed"`, `"safe"` / `"fast"`). An operator choosing a durability level is
choosing what survives what, and `fsync` is the word that has that meaning
precisely. `"safe"` would also make the *other* value read as "unsafe", which
overstates it — page-cache durability is a real property and is what the system
shipped with until now.

- **Loser: a boolean, `fsync = true`.** Reads fine at two levels and cannot
  grow a third without a breaking rename. The ROADMAP wording ("the durability
  *level*") anticipates a scale, and a string enum is what `[task_state].backend`
  already is.
- **Loser: three levels, adding `"fdatasync"`.** Measured out — 1687 µs against
  1649 µs on this filesystem, because an append changes the file size and the
  metadata flush happens either way. A level that costs a decision and buys
  nothing measurable is worse than no level.

### 2 · The key is in **both** loaders, and the two values need **not** agree

Both `warden.toml` and `control.toml` get the key, both default to `"fsync"`.

The two writers of this one file already share two values that **must** agree:
`[audit].path` (divergence is two chains, silently) and `[tokens].issuer`
(divergence fails every token, loudly). Both are documented with matching
comments in both TOMLs, and `[audit].path` has a shipped-pair test.

`durability` is deliberately **not** treated that way, because divergence here
is not a bug. A broker at `"flush"` and a control plane at `"fsync"` says: *the
grant must survive power loss; the decisions are high-volume and I accept the
risk on them.* That is a coherent tiering, and B7's own argument supports it —
the mint is the most powerful record in the system and the control plane writes
a handful per task, so it has no throughput reason to ever weaken.

So: a comment in both TOMLs saying they need not agree and what a mixed setting
means, and **no equality test**. A test asserting they match would pin a
constraint that does not exist and would fail a legitimate deployment.

- **Loser: the key in `warden.toml` only, with the control plane always
  fsyncing.** Makes the harmful divergence unconstructible and is genuinely
  attractive. It loses on the config surface: one file, two writers, and only
  one of them has the knob, which an operator reading `control.toml` has to be
  *told* rather than *shown*. A knob that exists for one writer and is invisible
  for the other is the kind of asymmetry that gets misremembered.
- **Loser: a constructor argument only, no TOML key at all** — exactly how
  `lock_timeout` works today. Divergence impossible, smallest surface. It loses
  because ROADMAP B2 says "the durability level **configurable**", and an
  operator who needs the throughput would have to fork the code.

### 3 · An unrecognised level is refused twice, and never falls back

At config load: `ConfigError`, naming the key and both levels, in the shape
`_task_state_config` already uses for `backend`. At construction:
`ValueError` from `AuditLog.__init__`.

Both, not one. The config check catches a typo in a TOML; the constructor check
catches every other caller — `warden/cli/replay.py`, `demo/cli/explain.py`, and
the tests — none of which go through the loader.

The failure must not be a fallback **in either direction**. Falling back to
`"flush"` is a silent weakening of exactly the kind `config/schema.py:130`
exists to prevent ("a typo that silently disables a check is precisely the
failure this module exists to make impossible"). Falling back to `"fsync"` is
silently *ignoring* what an operator wrote, which is how a deployment ends up
with a throughput profile nobody chose.

- **Loser: test `!= "flush"` rather than `== "fsync"`, so an unknown value
  fails safe.** Clever, and it makes the constructor check look unnecessary. It
  loses because "fails safe" here means "silently does the opposite of what the
  config file says", and because the cleverness is invisible at the call site.

### 4 · The `fsync` goes after `flush()`, inside the `with` block — so inside the `flock` by construction

```python
handle.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
handle.flush()
if self._durability == "fsync":
    os.fsync(handle.fileno())
```

**After `flush()`, necessarily.** `flush()` moves bytes from Python's buffer to
the kernel; `fsync` moves the kernel's pages to the device. Reversing them
would sync pages the bytes have not reached.

**Inside the `flock`, and the code shape makes that free.** The `flock` is
released when the handle closes at the end of the `with`, so anything inside
the block is inside the lock. There is no cheap way to write the wrong thing —
but there is an expensive way, and it is the loser below.

- **Loser: `fcntl.flock(handle.fileno(), fcntl.LOCK_UN)` before the `fsync`, to
  cut the lock hold from ~1.7 ms back to ~107 µs.** Rejected. It lets writer B
  read the tail, chain onto record N and have its own `append()` return, while
  record N is still only in the page cache. The chain is *content*-linked, so
  losing N while keeping N+1 leaves a `prev_hash` pointing at a record **nobody
  has** — unrepairable by replay, backup or anything else. That is the precise
  failure mode B6's design rejected the Redis-CAS option for, and it is not
  worth reintroducing for 1.6 ms. It is true that on ext4 an `fsync` of a later
  record happens to flush earlier dirty pages of the same file, which would
  mask this — but that is a filesystem behaviour, not a promise this code gets
  to make. And it loses a second time on the same axis B6 used: it adds an
  explicit unlock, whose interaction with a raising `fsync` and the implicit
  unlock at `close` is a second path to reason about, to save 1.6 ms in a call
  path that already contains an HTTP round-trip to OPA. Cheap is not the axis
  this file optimises.

The lock hold going from ~107 µs to ~1.7 ms is the real cost of this decision
and is stated in *What it costs* rather than buried.

### 5 · Record 1 also fsyncs the parent directory, and `seq == 0` is the trigger

`fsync` on the file descriptor makes the file's **contents** durable. It says
nothing about the **directory entry** that makes the file findable. On a
freshly created log, a power loss can therefore lose the whole file — including
record 1, whose `append()` returned and whose action went ahead.

The trigger costs **no extra syscall**. `_head_from_tail` already returns
`(0, GENESIS_HASH)` for an empty file, so `seq == 0` means precisely "this
append is record 1":

```python
    os.fsync(handle.fileno())
    if seq == 0:
        directory = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
```

~1.4 ms, once per log, on the one append that needs it.

Two notes. `_head_from_tail` also returns `seq == 0` for a file of nothing but
newlines, so such a file gets one needless directory `fsync` — 1.4 ms, once,
against a case the file already treats as "zero records". And `os.open` on a
directory is POSIX-only, which costs nothing: `audit.py` imports `fcntl` and
has been POSIX-only since B6.

- **Loser: `created = not self.path.exists()` before the `open`.** The obvious
  spelling, and it costs a `stat` on **every** append to learn something the
  tail read already knows. It is also *less* correct: a file that exists but is
  empty has an equally undurable directory entry, and `exists()` returns True
  for it.
- **Loser: fsync the parent in `__init__`, after `mkdir`.** The file does not
  exist yet at that point, so it does not make the file's entry durable — and
  it would charge every `warden replay` and `verify-chain` invocation 1.4 ms
  for a read-only operation.
- **Loser: skip it and document the gap.** Smaller diff, and it puts a stated
  hole in the promise at exactly the record the promise is most about.

### 6 · An `fsync` failure is an `OSError` into the machinery that already exists

`os.fsync` raises `OSError`. It propagates out of `append()` untouched, into
the spine's `except OSError`, its `AUDIT_UNAVAILABLE_*` outcomes and
`broker/proxy.py`'s best-effort branch — the same handlers `_acquire`'s timeout
was deliberately shaped for in B6, and the same ones B7's mint-refusal path
uses. **Zero new handling, zero new outcomes, zero interface change.**

One consequence is stated rather than fixed: when `fsync` fails, the record
line **has already been written and flushed**, so the file contains a record
for an action that was then refused. The log over-reports by one record and the
enforcement fails in the safe direction (nothing runs, the caller gets a 503).

- **Loser: truncate the line back off on an `fsync` failure.** Rejected on this
  file's own established precedent — `_head_from_tail` refuses to truncate a
  torn trailing line, because "an audit log that silently deletes a byte it did
  not like is not tamper-evident" (`audit.py:147-152`). A log that removes its
  own records under an I/O error is a log whose contents depend on how the
  disk was failing at the time. Also unsound: an `fsync` that failed may
  nonetheless have written.

### 7 · B6's correctness argument is untouched, and the code says so

It is worth being explicit, because this is the kind of thing that gets
misremembered as load-bearing. B6's inter-process correctness rests on the
bytes being in the **page cache** before the lock is released, so the next
process's tail read sees them. `flush()` is what puts them there. `fsync` is
about **power loss** and contributes nothing to inter-process visibility.

So the comment at `audit.py:242-244` ("Written and FLUSHED inside the lock…")
stays true and gains one sentence saying the `fsync` beneath it is not what
makes it true. Deleting the `fsync` would not break B6; deleting the `flush`
would.

### 8 · `lock_timeout` is **not** promoted to a config key, and the comment predicting it is corrected

`audit.py:28-34` currently argues that `_LOCK_TIMEOUT_SECONDS` is a constructor
default rather than a config knob, and then says: *"It becomes a knob when B2
adds `[audit].durability`, so the config surface changes once instead of
twice."*

B2 declines. The stated reason for bundling was to change the config surface
once — a real argument, but a "while we're here" one, and the substantive test
is whether anything now *needs* the timeout configurable. Nothing does: 5 s was
~47,000× an append before this change and is ~2,900× one after, and the worst
contention this design creates (16 threads, ~27 ms) is still two orders of
magnitude inside it. Adding a knob nobody needs to justify a knob somebody does
is backwards.

The comment must not survive unchanged either way — a comment asserting a
future that did not happen is exactly the drift this project punishes. It is
rewritten to say the timeout stayed a constant, and why, with the new
measurement.

### 9 · The durability level is **not** recorded in the record

A record that carried its own durability level would let `warden verify-chain`
report a mixed chain, which decision 2 makes possible. It is refused anyway.

`tests/golden/audit-4711.jsonl` is a **frozen** chain and
`tests/golden/replay-4711.txt` is a frozen rendering. A fourteenth body field
changes `canonical_json` for every record, so every hash in the golden file
changes, and the file is frozen precisely so that hashes computed today still
verify against a chain written months ago. The whole tamper-evidence property
is that the field set does not move.

- **Loser: record it.** The information is real and the cost is the golden
  chain. Not close.

### 10 · The shared vocabulary lives in `audit.py`, and the loader imports it — measured

`DURABILITY_LEVELS` and the default are needed by both `audit.py` (the
mechanism, and the constructor check) and `config/loader.py` (the boot check).
Defining them twice is how the two drift.

`audit.py` owns them, because it owns the mechanism and is deliberately
stdlib-only — `fcntl`, `hashlib`, `json`, `os`, `threading`, `time`,
`datetime`, `pathlib`, `typing` and nothing from `warden`. B7's trap says
measure the import graph before adding an edge that reaches the process holding
the private signing key. Measured:

```
warden.broker.control_main today: 9 warden modules, including warden.broker.audit
warden.broker.config.loader alone: 4 -> 5 (warden.broker.audit, stdlib-only)
```

**Zero new modules in the signing process**, because `control_main` already
imports `AuditLog` to construct one. No new module is needed the way B7 needed
`record_fields.py`.

- **Loser: define the levels in `loader.py` and have `audit.py` import them.**
  Reverses the dependency so the append path — which `warden replay` uses
  standalone — would drag in the TOML loader.
- **Loser: a third stdlib-only module, mirroring `record_fields.py`.** B7
  needed one because the alternative was importing `spine`, which drags in
  `taint` and `adapters.base`. Here the alternative costs nothing, so the
  module would be ceremony.

---

## What changes

**`warden/broker/audit.py`**

- `DURABILITY_LEVELS = ("fsync", "flush")` and `DEFAULT_DURABILITY = "fsync"`,
  public because the loader imports them.
- `__init__` takes `durability: str = DEFAULT_DURABILITY`, keyword-only like
  `lock_timeout`, and raises `ValueError` on anything else. It is stored as
  **`self.durability`, public**, alongside the already-public `self.path` —
  which is what lets proof-table row 13 assert the result of the wiring rather
  than mock the call (see *What the review changed*, item 5).
- `append` gains the `fsync` after `flush()`, and the parent-directory `fsync`
  when `seq == 0`.
- Three comments change: `_LOCK_TIMEOUT_SECONDS`'s prediction (decision 8), the
  flush comment (decision 7), and a new one on the `fsync` itself.

**`warden/broker/config/loader.py`**

- `_durability(section, table)` — optional key, defaulted, `ConfigError` on an
  unrecognised value.
- `BrokerConfig.audit_durability` and `ControlConfig.audit_durability`, both
  next to `audit_path`. Both dataclasses are constructed **only** in this file
  — checked, not assumed (*What the review changed*, item 7) — so field
  placement is free and neither needs a default to keep call sites working.
- Both `load_broker_config` and `load_control_config` read it.

**`warden/broker/__main__.py:163`** and **`warden/broker/control_main.py:47`** —
`AuditLog(config.audit_path, durability=config.audit_durability)`. This is the
step whose omission would leave the key parsed and never consumed, which is the
failure `BrokerConfig.issuer`'s own comment warns about; it gets a test on each
side.

**`demo/scenario/warden.toml`** and **`demo/scenario/control.toml`** — the key,
named explicitly with the safe value, plus a comment giving the cost and saying
the two need not agree.

**`docs/ROADMAP.md`** — the B2 row becomes **Done**; the "not crash-durable"
paragraph loses its fsync sentence *and* its stale `threading.Lock` sentence
(see *What the review changed*, item 1).

**`docs/DEPLOYMENT.md`** — the audit bullets in *Required* gain the knob, the
default and the ceiling.

**`README.md`** — **no change, checked rather than assumed.** Its per-step table
makes a durability claim that B2 makes true, not a latency claim that B2 moves,
and its *Known limitations* list never contained a crash-durability entry to
delete.

---

## Proof table

Every row is a test that must be **watched go red** under the named mutation
and green again on revert. A row is an intention until then.

| # | Test | Mutation that must redden it |
|---|---|---|
| 1 | `test_audit_durability_defaults_to_the_safe_level` | `DEFAULT_DURABILITY = "flush"` |
| 2 | `test_the_control_plane_defaults_to_the_safe_level` | same |
| 3 | `test_an_unrecognised_broker_durability_is_a_config_error` | `_durability` returns the default instead of raising |
| 4 | `test_an_unrecognised_control_durability_is_a_config_error` | same |
| 5 | `test_the_two_writers_may_choose_different_durability` | add an equality check across the two configs |
| 6 | `test_an_unrecognised_durability_is_refused_by_the_constructor` | delete the `ValueError` |
| 7 | `test_an_append_fsyncs_the_log_before_returning` | delete `os.fsync(handle.fileno())` |
| 8 | `test_flush_durability_does_not_fsync` | make the `fsync` unconditional |
| 9 | `test_the_first_record_also_fsyncs_the_directory` | delete the directory `fsync` |
| 10 | `test_later_records_do_not_fsync_the_directory` | change `if seq == 0` to unconditional |
| 11 | `test_a_failed_fsync_refuses_the_append_as_an_oserror` | wrap the `fsync` in `try/except OSError: pass` |
| 12 | `test_the_fsync_happens_while_the_lock_is_still_held` | `LOCK_UN` before the `fsync` (decision 4's loser, made real) |
| 13 | `test_the_broker_builds_its_audit_log_with_the_configured_durability` | drop the kwarg at `__main__.py:163` |
| 14 | `test_the_control_plane_builds_its_audit_log_with_the_configured_durability` | drop the kwarg at `control_main.py:47` |
| 15 | `test_the_shipped_configs_name_the_safe_durability` | set `durability = "flush"` in either shipped TOML |

Three rows need their mechanism named, because each has one non-obvious step:

- **Row 12 is the load-bearing one.** It asserts the ordering decision 4 exists
  for, by replacing `os.fsync` with a spy that launches a **separate process**
  (`subprocess.Popen([sys.executable, "-c", ...])`, never `multiprocessing` —
  see the trap list) which attempts `flock(LOCK_EX | LOCK_NB)` on the log and
  must fail with `BlockingIOError`. The log is **pre-seeded with one record**
  so the append under test is record 2 and fires exactly one `fsync`.
- **Row 13** reads the result, not the call: `app, components =
  broker_main.build(config, client=stub_client())`, then
  `components.audit.durability`. It needs `test_key_split.py`'s
  `write_warden_toml` to take a `durability` kwarg and its `set_catalog_env`
  fixture.
- **Row 14** cannot do that, because `control_main.build()` returns only the
  app. It patches a capturing `AuditLog` subclass into `control_main` and
  asserts the constructor received `durability="flush"`; dropping the kwarg
  makes the captured mapping lack the key.

Row 15 asserts each shipped file names the safe value; it deliberately does
**not** assert the two match (decision 2).

Existing tests that must keep passing unchanged, and which pin decision 9:
`test_a_written_record_has_exactly_these_fields`, `test_golden_replay.py`,
`test_golden_decisions.py`.

Three traps this project has recorded apply directly and are called out for
the implementer:

- **A `pytest.raises(match=...)` substring can pass against the change it
  guards.** Rows 3, 4 and 6 must match the whole distinguishing message, not
  the word `durability` — which would also appear in the fallback error.
- **A mutation string must be unique.** `handle.flush()` appears once in
  `audit.py` but `os.fsync` will appear twice after this change; rows 7 and 9
  must name distinct strings and each mutation must assert `count(old) == 1`.
- **Read the failing test names out of pytest**, rather than trusting this
  table.

---

## What this does not do

- **It does not make `fsync` mean more than the hardware means.** A device that
  acknowledges a cache flush it has not performed defeats this, as it defeats
  every database. The numbers above are WSL2-on-a-virtual-disk numbers, where
  the guarantee against a *Windows host* power loss is weaker still.
- **It does not fsync the directory tree `__init__` creates.** `mkdir(parents=True)`
  can create several directories, and only the log's immediate parent is
  fsynced, on record 1. A power loss that lands between a first-ever boot and
  the first record can therefore still lose the log — a deployment whose volume
  was empty seconds earlier, which is a visible failure rather than a silent
  gap in a chain.
- **It does not let the log report its own durability.** Decision 2 permits a
  mixed deployment and decision 9 refuses to record the level, so "was this
  record fsynced" is answerable from the configs and not from the chain.
- **It does not touch rotation (B3), segments (B4), or the pluggable sink
  (B5).** It composes with all three: the `fsync` is inside the `flock`, which
  B3's anchor record will also be.
- **It does not address the cross-host case.** `flock` is per-kernel; two hosts
  sharing one log over NFS are not covered, and `fsync` does not change that.
  B5.
- **It does not move the process model.** There is still no `/healthz`, no
  `/readyz`, no `SO_REUSEPORT`, and `__main__.py:225` still binds the proxy
  inside the same `asyncio.run` as uvicorn. § A's exit criterion remains unmet
  and Phase 3 is still the gate.
