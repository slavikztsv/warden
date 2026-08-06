# P2·B2 — audit durability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `AuditLog.append()` returns only once the record is on stable storage,
with the level configurable per writer and the safe level as the default.

**Architecture:** One `os.fsync` after the existing `handle.flush()`, inside the
`with` block and therefore inside B6's `flock` by construction, plus a
parent-directory `fsync` on record 1 so the file's directory entry is durable
too. The level is a two-value string enum owned by `audit.py`, read from
`[audit].durability` by both loaders and passed to the constructor by both
construction sites.

**Tech Stack:** CPython 3.12, stdlib only (`os`, `fcntl`), `tomllib`, pytest.

## Global Constraints

- Design: [`docs/superpowers/specs/2026-08-06-p2b2-audit-durability-design.md`](../specs/2026-08-06-p2b2-audit-durability-design.md). Ten decisions, 15 proof-table rows.
- Levels are exactly `("fsync", "flush")`; the default is `"fsync"` in every layer.
- **Zero interface changes.** `append()`'s signature, the thirteen body fields
  and the record's key set do not move. `tests/golden/audit-4711.jsonl` is a
  **frozen** chain — never regenerate or hand-edit it.
- **No record count anywhere changes.** No doc that counts records is touched.
- An unrecognised level raises — `ConfigError` at load, `ValueError` at
  construction — and never falls back in either direction.
- `pytest.raises(match=...)` must match the **whole distinguishing message**, not
  a substring that the fallback error would also contain.
- Every mutation must assert its search string is **unique** (`count(old) == 1`)
  and must be reverted with `__pycache__` cleared:
  `find . -path ./.venv -prune -o -name '__pycache__' -type d -exec rm -rf {} +`
- Five gates before every commit:
  ```
  .venv/bin/pytest -q
  .venv/bin/ruff check .
  .venv/bin/mypy warden --ignore-missing-imports
  opa test warden/policies/ demo/scenario/data.json
  .venv/bin/warden-demo explain --quiet-why
  ```

## File Structure

| File | Responsibility after this change |
|---|---|
| `warden/broker/audit.py` | Owns the durability vocabulary and the mechanism. Stdlib-only; must stay so. |
| `warden/broker/config/loader.py` | Reads `[audit].durability` in both loaders; imports the vocabulary from `audit.py`. |
| `warden/broker/__main__.py` | Passes `config.audit_durability` into the broker's `AuditLog`. |
| `warden/broker/control_main.py` | Same for the control plane's. |
| `demo/scenario/warden.toml`, `demo/scenario/control.toml` | The reference configs name the key explicitly. |
| `tests/warden/test_audit.py` | Rows 6–12: the mechanism. |
| `tests/warden/test_config_loader.py` | Rows 1–5: the config surface. |
| `tests/warden/test_key_split.py` | Rows 13–14: the wiring, on both sides. |
| `tests/demo/test_cli.py` | Row 15: the shipped pair each names the safe value. |
| `docs/ROADMAP.md`, `docs/DEPLOYMENT.md` | The claim deletions and the operator guidance. |

**Two commits, not one** (the spec's header is updated to match in Task 5):
Task 1 is a complete, independently green change — the log becomes durable, with
no way to turn it off. Tasks 2–4 make it configurable and move the docs. A
reviewer can reject either half without rejecting the other.

---

### Task 1: The mechanism — `fsync` inside the lock, and the directory on record 1

**Files:**
- Modify: `warden/broker/audit.py` (constants near line 34, `__init__` at 157, `append`'s tail at 245)
- Test: `tests/warden/test_audit.py` (append at end)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `warden.broker.audit.DURABILITY_LEVELS: tuple[str, str]`,
  `warden.broker.audit.DEFAULT_DURABILITY: str`, and
  `AuditLog(path, *, lock_timeout: float = ..., durability: str = DEFAULT_DURABILITY)`
  exposing a **public** `self.durability: str`. Task 2 imports the two module
  constants; Task 3 reads `components.audit.durability`.

- [ ] **Step 1: Write the seven failing tests**

Append to `tests/warden/test_audit.py`. `os` and `subprocess`/`sys` are needed —
`subprocess` and `sys` are already imported at the top; add `import os`.

```python
# --- B2: durability -------------------------------------------------------
#
# Designed in docs/superpowers/specs/2026-08-06-p2b2-audit-durability-design.md.
# These assert the SYSCALL, not the physics: there is no way to power-cycle a
# host from pytest. What they pin is that the log's own descriptor is fsynced,
# on the append, before append() returns -- and that the parent directory is
# fsynced on the one append that creates the file.


def _fsync_spy(seen: list[int]):
    """Records the inode behind every fsynced fd, then really fsyncs."""
    real = os.fsync

    def spy(fd: int) -> None:
        seen.append(os.fstat(fd).st_ino)
        real(fd)

    return spy


def test_an_append_fsyncs_the_log_before_returning(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)  # record 1 also fsyncs the directory; keep this append clean
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        _append(log)
    assert os.stat(path).st_ino in seen


def test_flush_durability_does_not_fsync(tmp_path):
    """The level that shipped before B2, kept reachable and named."""
    log = AuditLog(tmp_path / "audit.jsonl", durability="flush")
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        record = _append(log)
    assert seen == []
    # Still a real, readable, chained record -- "flush" weakens durability and
    # nothing else.
    assert record["seq"] == 1
    assert log.records() == [record]
    assert log.verify_chain() == (True, None)


def test_the_first_record_also_fsyncs_the_directory(tmp_path):
    """fsync on the file makes its CONTENTS durable, not its directory entry.

    Without this, a power loss shortly after a log is first created loses the
    whole file -- including record 1, whose append() already returned and whose
    action therefore went ahead.
    """
    path = tmp_path / "audit.jsonl"
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        AuditLog(path).append(
            task_id="4711",
            agent_id="triage-bot",
            purpose="support-triage",
            action={"type": "tool_call", "tool": "read_document"},
            target={"kind": "doc"},
            args_digest="sha256:aaa",
            decision="allow",
            rule="tools.allowed",
            task_state={"data_classes_held": [], "rows_charged_so_far": 0},
            policy_bundle_digest="sha256:bbb",
        )
    assert os.stat(path).st_ino in seen
    assert os.stat(tmp_path).st_ino in seen


def test_later_records_do_not_fsync_the_directory(tmp_path):
    """Once per log, on the append that creates it -- not 1.4ms on every one."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)
    seen: list[int] = []
    with patch.object(os, "fsync", _fsync_spy(seen)):
        _append(log)
    assert os.stat(tmp_path).st_ino not in seen


def test_an_unrecognised_durability_is_refused_by_the_constructor(tmp_path):
    """Never a fallback, in EITHER direction. Falling back to "flush" silently
    weakens the log; falling back to "fsync" silently ignores what was written.
    """
    with pytest.raises(
        ValueError,
        match=r"audit durability must be one of \('fsync', 'flush'\), got 'fsyncc'",
    ):
        AuditLog(tmp_path / "audit.jsonl", durability="fsyncc")


def test_a_failed_fsync_refuses_the_append_as_an_oserror(tmp_path):
    """Into the machinery that already exists: spine.py catches OSError at all
    four of its _append sites and control.py:178 catches it around record_mint,
    so a failing disk becomes a 503 with nothing executed.

    The written line STAYS. This log does not delete bytes it did not like --
    the same rule _head_from_tail states for a torn trailing line. The
    consequence is stated rather than fixed: the file over-reports by one
    record, and the enforcement failed in the safe direction.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)

    def failing(fd: int) -> None:
        raise OSError("input/output error")

    with patch.object(os, "fsync", failing):
        with pytest.raises(OSError, match="input/output error"):
            _append(log)
    assert len(log.records()) == 1


_LOCK_PROBE = """
import fcntl, sys
handle = open(sys.argv[1], "a+b")
try:
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("held")
else:
    print("free")
"""


def test_the_fsync_happens_while_the_lock_is_still_held(tmp_path):
    """The load-bearing ordering, and the reason the lock hold went 16x.

    Releasing the flock before the fsync would let writer B read the tail,
    chain onto record N and have its own append() return while N is still only
    in the page cache. The chain is CONTENT-linked, so losing N while keeping
    N+1 leaves a prev_hash pointing at a record nobody has -- unrepairable by
    replay, backup or anything else, and the precise failure B6 rejected the
    Redis-CAS design for.

    A fresh interpreter, never multiprocessing: tests/ has no __init__.py and
    pytest.ini sets --import-mode=importlib, so a spawn child cannot re-import
    the test module, and forking a multi-threaded pytest process is a
    documented deadlock hazard.
    """
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    _append(log)  # so the append under test fires exactly one fsync

    seen: list[str] = []
    real = os.fsync

    def probing(fd: int) -> None:
        seen.append(
            subprocess.run(
                [sys.executable, "-c", _LOCK_PROBE, str(path)],
                capture_output=True,
                text=True,
                timeout=120,
            ).stdout.strip()
        )
        real(fd)

    with patch.object(os, "fsync", probing):
        _append(log)

    assert seen == ["held"]
```

- [ ] **Step 2: Run them and watch all seven fail**

```bash
.venv/bin/pytest tests/warden/test_audit.py -q -k "fsync or durability" 2>&1 | tail -20
```

Expected: 7 failed. Six fail on the missing `fsync` (`assert ... in []`,
`seen == []` where a `[]` was expected to be non-empty is the exception — read
each failure rather than assuming), one on `TypeError: __init__() got an
unexpected keyword argument 'durability'`.

- [ ] **Step 3: Add the vocabulary to `warden/broker/audit.py`**

After `_TAIL_WINDOW_BYTES` (line 44), before `_BODY_FIELDS`:

```python
# The two durability levels, and what each promises.
#
#   "fsync" -- the record is on STABLE STORAGE before append() returns. It
#     survives the host losing power, which is what makes README's "write the
#     decision down, BEFORE anything happens" true rather than nearly true.
#   "flush" -- the record is in the kernel's page cache before append()
#     returns. It survives this process being killed, not the host. This is
#     what shipped before B2, kept reachable and named.
#
# Named for the SYSCALL rather than for a promise ("safe"/"fast"): an operator
# choosing a level is choosing what survives what, and calling the other one
# "unsafe" would overstate it -- page-cache durability is a real property and
# is what this system shipped with until now.
#
# Two levels, not three. `fdatasync` is the usual cheaper `fsync`, and it is
# measured indistinguishable here -- 1687us against 1649us, inside the noise --
# because an append CHANGES THE FILE SIZE, so the metadata flush it exists to
# skip happens anyway. A level that costs a decision and buys nothing measurable
# is worse than no level.
DURABILITY_LEVELS = ("fsync", "flush")
DEFAULT_DURABILITY = "fsync"
```

- [ ] **Step 4: Take the constructor argument**

Replace `AuditLog.__init__`'s signature and add the check and the attribute:

```python
    def __init__(
        self,
        path: Path,
        *,
        lock_timeout: float = _LOCK_TIMEOUT_SECONDS,
        durability: str = DEFAULT_DURABILITY,
    ) -> None:
        if durability not in DURABILITY_LEVELS:
            # Never a fallback, in either direction. Falling back to "flush"
            # silently weakens the log, which is the failure
            # config/schema.py's parse_tool_schema exists to prevent; falling
            # back to "fsync" silently ignores what a caller wrote, which is
            # how a deployment acquires a throughput profile nobody chose.
            raise ValueError(
                f"audit durability must be one of {DURABILITY_LEVELS}, "
                f"got {durability!r}"
            )
        self.path = Path(path)
        # PUBLIC, alongside `path`: broker/__main__.py's build() returns its
        # BrokerComponents, so a test can assert the configured level actually
        # reached the log rather than mocking the constructor call.
        self.durability = durability
        self.path.parent.mkdir(parents=True, exist_ok=True)
```

(The rest of `__init__` — the `threading.Lock` and `_lock_timeout` — is
unchanged and stays below this.)

- [ ] **Step 5: Add the two `fsync` calls to `append`**

Replace the tail of `append` (currently `handle.flush()` then `return record`):

```python
                handle.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
                handle.flush()
                if self.durability == "fsync":
                    # B2. flush() reaches the kernel; this reaches the device.
                    # INSIDE the lock, which the `with` gives for free -- the
                    # flock is released by the close at the end of the block.
                    # Releasing it early to shorten the ~1.7ms hold would let
                    # the next writer chain onto a record that is still only in
                    # the page cache, and a content-linked chain that loses N
                    # while keeping N+1 has a prev_hash nobody can supply.
                    os.fsync(handle.fileno())
                    if seq == 0:
                        # This append CREATED the file (seq is the head's, so
                        # zero means the log had no records). fsync on the file
                        # makes its contents durable and says nothing about the
                        # DIRECTORY ENTRY that makes it findable, so without
                        # this a power loss can lose the whole log -- including
                        # record 1, whose append() already returned and whose
                        # action therefore went ahead. ~1.4ms, once per log.
                        directory = os.open(self.path.parent, os.O_RDONLY)
                        try:
                            os.fsync(directory)
                        finally:
                            os.close(directory)
                return record
```

- [ ] **Step 6: Correct the two comments that this change makes wrong**

In `_LOCK_TIMEOUT_SECONDS`'s comment, replace the final sentence — *"It becomes
a knob when B2 adds `[audit].durability`, so the config surface changes once
instead of twice."* — with:

```
# B2 arrived, added `[audit].durability`, and deliberately did NOT bring this
# with it. Bundling would have changed the config surface once instead of
# twice, which is a real argument and a "while we're here" one; the
# substantive test is whether anything now NEEDS the timeout configurable.
# Nothing does. Five seconds was ~47,000x an append before B2 and is ~2,900x
# one after, and the worst contention B2 creates -- sixteen threads at ~1.7ms
# each, ~27ms -- is still two orders of magnitude inside it.
```

In the comment above `handle.write` (currently ending *"Releasing before the
bytes are out would let the next writer read a tail that is still in a
userspace buffer."*), append:

```
                # The fsync below is NOT what makes that true, and it is worth
                # saying so because this is the kind of thing that gets
                # misremembered as load-bearing: B6's inter-process correctness
                # is the PAGE CACHE serving the next process's tail read, which
                # flush() is what provides. fsync is about power loss. Deleting
                # the fsync would not break B6; deleting the flush would.
```

- [ ] **Step 7: Run the seven tests and the whole audit suite**

```bash
.venv/bin/pytest tests/warden/test_audit.py -q 2>&1 | tail -5
```

Expected: 24 passed (17 existing + 7 new).

- [ ] **Step 8: Run the five gates, then commit**

```bash
.venv/bin/pytest -q && .venv/bin/ruff check . && \
  .venv/bin/mypy warden --ignore-missing-imports && \
  opa test warden/policies/ demo/scenario/data.json && \
  .venv/bin/warden-demo explain --quiet-why | tail -20
```

Expected: 844 passed; ruff clean; mypy clean; 53 OPA tests; the demo showing
**8 records, 3 refusals, 1 record read** — unchanged, because B2 adds no
records.

```bash
git add warden/broker/audit.py tests/warden/test_audit.py
git commit
```

Commit message states: the measured 16× and that it is flat in log size, the
`fdatasync` equivalence, that the fsync is inside the flock and why, and the
directory fsync on `seq == 0`.

---

### Task 2: The config surface — `[audit].durability` in both loaders

**Files:**
- Modify: `warden/broker/config/loader.py` (import; `_durability` helper near `_positive`; `BrokerConfig`; `ControlConfig`; both `load_*` functions)
- Test: `tests/warden/test_config_loader.py`

**Interfaces:**
- Consumes: `DURABILITY_LEVELS`, `DEFAULT_DURABILITY` from Task 1.
- Produces: `BrokerConfig.audit_durability: str` and
  `ControlConfig.audit_durability: str`, both required fields (the dataclasses
  are constructed only in `loader.py`). Task 3 reads both.

- [ ] **Step 1: Write the five failing tests**

Append the broker ones after the existing broker-config tests, and the control
ones after `test_control_loads_every_field`:

```python
def test_audit_durability_defaults_to_the_safe_level(tmp_path):
    """ROADMAP B2: "the default being the safe one". A config written before
    this key existed gets the STRONGER behaviour, never the weaker."""
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.audit_durability == "fsync"


def test_an_unrecognised_broker_durability_is_a_config_error(tmp_path):
    text = COMPLETE.replace(
        '[audit]\npath = "/data/audit.jsonl"',
        '[audit]\npath = "/data/audit.jsonl"\ndurability = "fsyncc"',
    )
    with pytest.raises(
        ConfigError,
        match=re.escape(
            "audit.durability must be one of ('fsync', 'flush'), got 'fsyncc'"
        ),
    ):
        load_broker_config(write(tmp_path, text), env={})


def test_the_control_plane_defaults_to_the_safe_level(tmp_path):
    config = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    assert config.audit_durability == "fsync"


def test_an_unrecognised_control_durability_is_a_config_error(tmp_path):
    text = CONTROL_COMPLETE.replace(
        '[audit]\npath = "/data/audit.jsonl"',
        '[audit]\npath = "/data/audit.jsonl"\ndurability = 3',
    )
    with pytest.raises(
        ConfigError,
        match=re.escape("audit.durability must be one of ('fsync', 'flush'), got 3"),
    ):
        load_control_config(write_control(tmp_path, text), env={})


def test_the_two_writers_may_choose_different_durability(tmp_path):
    """Unlike [audit].path and [tokens].issuer -- which MUST agree, and whose
    divergence is a silent bug and a loud one respectively -- a broker at
    "flush" and a control plane at "fsync" is a coherent tiering: the grant
    must survive power loss, the high-volume decisions accept the risk.

    So there is deliberately NO test that the two agree, and this is the test
    that pins the absence.
    """
    broker = load_broker_config(
        write(
            tmp_path,
            COMPLETE.replace(
                '[audit]\npath = "/data/audit.jsonl"',
                '[audit]\npath = "/data/audit.jsonl"\ndurability = "flush"',
            ),
        ),
        env={},
    )
    control = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    assert broker.audit_durability == "flush"
    assert control.audit_durability == "fsync"
    assert broker.audit_path == control.audit_path
```

Also extend the two existing whole-config assertions — a field-by-field test
that claims to load *every* field and omits one is a trap this project has
already been bitten by:

- in `test_loads_every_field`, add `assert config.audit_durability == "fsync"`
- in `test_control_loads_every_field`, add `assert config.audit_durability == "fsync"`

- [ ] **Step 2: Run them and watch all five fail**

```bash
.venv/bin/pytest tests/warden/test_config_loader.py -q -k durability 2>&1 | tail -20
```

Expected: 5 failed on `AttributeError: 'BrokerConfig' object has no attribute
'audit_durability'` and, for the two error tests, `DID NOT RAISE`.

- [ ] **Step 3: Import the vocabulary**

At the top of `warden/broker/config/loader.py`, after the stdlib imports:

```python
from warden.broker.audit import DEFAULT_DURABILITY, DURABILITY_LEVELS
```

Measured: `control_main`'s import graph is 9 `warden` modules and already holds
`warden.broker.audit`, so this adds **zero** modules to the process that holds
the private signing key. `audit.py` is stdlib-only and must stay so.

- [ ] **Step 4: Add the `_durability` helper**

After `_positive` (line 214):

```python
def _durability(section: dict, table: str) -> str:
    """[audit].durability -- optional, defaulted to the safe level.

    Optional because every config written before this key existed must keep
    loading, and safe-by-default because those configs then get the STRONGER
    behaviour rather than the weaker one.

    An unrecognised value raises rather than falling back in EITHER direction.
    Falling back to "flush" silently weakens the log, which is the failure
    config/schema.py exists to prevent ("a typo that silently disables a check
    is precisely the failure this module exists to make impossible"). Falling
    back to "fsync" silently ignores what an operator wrote. The membership
    test also type-checks for free: `durability = 3` is not in the tuple.
    """
    value = section.get("durability", DEFAULT_DURABILITY)
    if value not in DURABILITY_LEVELS:
        raise ConfigError(
            f"{table}.durability must be one of {DURABILITY_LEVELS}, got {value!r}"
        )
    return value
```

- [ ] **Step 5: Add the field to both dataclasses and both loaders**

In `BrokerConfig`, immediately after `audit_path: Path`:

```python
    # "fsync" or "flush". Unlike audit_path and issuer -- the two values these
    # two processes MUST agree on -- this one need NOT match control.toml's. A
    # broker at "flush" and a control plane at "fsync" says "the grant must
    # survive power loss; the high-volume decisions accept the risk", which is
    # a coherent tiering rather than a misconfiguration. Nothing compares them
    # and nothing should.
    audit_durability: str
```

In `ControlConfig`, immediately after `audit_path: Path`:

```python
    # "fsync" or "flush", and unlike audit_path directly above it this one need
    # NOT match warden.toml's. See BrokerConfig.audit_durability.
    audit_durability: str
```

In `load_broker_config`'s and `load_control_config`'s return expressions, after
each `audit_path=...` line:

```python
        audit_durability=_durability(audit, "audit"),
```

- [ ] **Step 6: Run the config suite**

```bash
.venv/bin/pytest tests/warden/test_config_loader.py -q 2>&1 | tail -5
```

Expected: all pass, 5 more than before.

---

### Task 3: The wiring — both construction sites and both shipped configs

**Files:**
- Modify: `warden/broker/__main__.py:163`, `warden/broker/control_main.py:47`, `demo/scenario/warden.toml`, `demo/scenario/control.toml`
- Test: `tests/warden/test_key_split.py`, `tests/demo/test_cli.py`

**Interfaces:**
- Consumes: `AuditLog(..., durability=...)` and `self.durability` from Task 1;
  `config.audit_durability` from Task 2.
- Produces: nothing later tasks depend on.

This is the step whose omission leaves the key parsed and never consumed —
exactly the failure `BrokerConfig.issuer`'s own comment warns about. Both sides
get a test, and they are **not** symmetric: `broker_main.build()` returns
`(app, components)`, `control_main.build()` returns only the app.

- [ ] **Step 1: Write the three failing tests**

In `tests/warden/test_key_split.py`, first give `write_warden_toml` and
`write_control_toml` a `durability` knob. Each writes an `[audit]` section;
add a `durability: str = "fsync"` keyword parameter to both signatures and
`durability = "{durability}"` to the `[audit]` block each one writes.

Then:

```python
def test_the_broker_builds_its_audit_log_with_the_configured_durability(
    tmp_path, monkeypatch
):
    """The step whose omission leaves the key parsed and never consumed."""
    set_catalog_env(monkeypatch, tmp_path)
    _, public_key = write_keypair(tmp_path)
    config = broker_config(tmp_path, public_key, durability="flush")
    _, components = broker_main.build(config, client=stub_client())
    assert components.audit.durability == "flush"


def test_the_control_plane_builds_its_audit_log_with_the_configured_durability(
    tmp_path, monkeypatch
):
    """control_main.build() returns only the app -- the log is a closure
    argument to create_control_app and nothing exposes it -- so this captures
    the construction instead of reading the result."""
    private_key, _ = write_keypair(tmp_path)
    captured: dict = {}

    class Capturing(AuditLog):
        def __init__(self, path, **kwargs):
            captured.update(kwargs)
            super().__init__(path, **kwargs)

    monkeypatch.setattr(control_main, "AuditLog", Capturing)
    control_main.build(control_config(tmp_path, private_key, durability="flush"))
    assert captured["durability"] == "flush"
```

`test_key_split.py` already imports `broker_main`, `control_main` and builds
keypairs; add `from warden.broker.audit import AuditLog` if it is not already
imported. `write_keypair` returns `(private_path, public_path)` — check the
order at the call site rather than trusting this plan.

In `tests/demo/test_cli.py`:

```python
def test_the_shipped_configs_name_the_safe_durability():
    """Each names it explicitly -- the reference configs document the knob.

    Deliberately NOT an equality check between the two: they need not agree
    (see the B2 design, decision 2), and a test asserting they match would fail
    a legitimate deployment.
    """
    root = Path(__file__).resolve().parents[2] / "demo" / "scenario"
    for name in ("warden.toml", "control.toml"):
        assert 'durability = "fsync"' in (root / name).read_text(), name
```

- [ ] **Step 2: Run them and watch all three fail**

```bash
.venv/bin/pytest tests/warden/test_key_split.py tests/demo/test_cli.py -q -k durability 2>&1 | tail -20
```

Expected: 3 failed — two on `assert 'fsync' == 'flush'` (the default reaching
the log because the kwarg is not passed), one on the missing TOML line.

- [ ] **Step 3: Pass the level at both construction sites**

`warden/broker/__main__.py:163`:

```python
        audit=AuditLog(config.audit_path, durability=config.audit_durability),
```

`warden/broker/control_main.py:47`:

```python
    return create_control_app(
        signer=signer,
        audit=AuditLog(config.audit_path, durability=config.audit_durability),
        issuer=config.issuer,
    )
```

- [ ] **Step 4: Name the key in both shipped configs**

In `demo/scenario/warden.toml`'s `[audit]` block, under the existing `path`:

```toml
# "fsync" (the default) or "flush". "fsync" means append() returns only once
# the record is on the disk, so it survives the host losing power -- measured
# at ~1.7ms against ~107us, flat in log size, and the whole deployment's audit
# ceiling is then ~590 records/second. "flush" returns once the record is in
# the kernel's page cache: it survives this process dying, not the host.
#
# This one need NOT match control.toml's, unlike `path` above. A broker at
# "flush" with a control plane at "fsync" is a coherent tiering, not a
# misconfiguration.
durability = "fsync"
```

In `demo/scenario/control.toml`'s `[audit]` block, under the existing `path`:

```toml
# "fsync" (the default) or "flush". Unlike `path` above, this need NOT match
# warden.toml's -- see the note there. The control plane writes a handful of
# mint records per task, so it has no throughput reason to ever weaken.
durability = "fsync"
```

- [ ] **Step 5: Run the three tests, then the full suite**

```bash
.venv/bin/pytest tests/warden/test_key_split.py tests/demo/test_cli.py -q 2>&1 | tail -5
.venv/bin/pytest -q 2>&1 | tail -3
```

Expected: all pass.

---

### Task 4: The docs — two claim deletions and one operator paragraph

**Files:**
- Modify: `docs/ROADMAP.md` (the B2 table row at 334; the "not crash-durable" paragraph at 113–124), `docs/DEPLOYMENT.md` (the audit bullets in *Required*, around line 72)

**Interfaces:** none.

`README.md` is **not** touched, and that is a decision rather than an omission:
its per-step table already claims "Write the decision down, **before** anything
happens" unqualified, so B2 makes an existing claim true rather than requiring
a new one, and its *Known limitations* list never carried a crash-durability
entry to delete.

- [ ] **Step 1: Rewrite the ROADMAP paragraph, including the stale B6 sentence**

Lines 120–124 currently read:

> Separately, `append()` calls `handle.flush()` with no `os.fsync()` — so "the
> decision is written down **before** anything happens", the property the whole
> design turns on, is durable against a process crash but not against a host
> loss. The claim is stronger than the code. Its `threading.Lock` is also
> process-local, so a second worker breaks the chain rather than slowing it.

**Both** sentences go. The first is what B2 closes. The second was already
falsified by B6 — it survived because B6 rewrote the table row and not this
paragraph — and leaving it while deleting its neighbour would produce a
paragraph half of which is current. Replace with a struck-through version plus
the account, matching the strikethrough style the rest of the paragraph uses.

- [ ] **Step 2: Mark B2 done in the § B table**

Row B2 becomes `~~`os.fsync` before returning from `append()`…~~ **Done.**`
followed by: the level is `[audit].durability` in both TOMLs defaulting to
`"fsync"`; the two need not agree and that is deliberate; record 1 also fsyncs
the parent directory; measured 16× (~107 µs → ~1.7 ms), flat in log size, and
`fdatasync` measured indistinguishable so there is no third level.

- [ ] **Step 3: Extend the DEPLOYMENT audit bullets**

The *Required* bullet "Give the broker a writable audit path…" gains the knob,
the default, the measured cost and the ceiling (~590 records/second for the
whole deployment, because appends serialize under the `flock`). The control
plane's bullet gains one sentence: the durability key need not match, unlike
the path directly above it.

- [ ] **Step 4: Run the gates and commit tasks 2–4 together**

```bash
.venv/bin/pytest -q && .venv/bin/ruff check . && \
  .venv/bin/mypy warden --ignore-missing-imports && \
  opa test warden/policies/ demo/scenario/data.json && \
  .venv/bin/warden-demo explain --quiet-why | tail -20
```

```bash
git add warden/broker/config/loader.py warden/broker/__main__.py \
        warden/broker/control_main.py demo/scenario/warden.toml \
        demo/scenario/control.toml tests/ docs/ROADMAP.md docs/DEPLOYMENT.md
git commit
```

---

### Task 5: Verify by mutation — all fifteen rows

**Files:** none permanently. Every mutation is reverted.

A proof table is a list of intentions until each row has been made to fail.
**Commit before mutating** (Tasks 1 and 4 both end in a commit, so this is
satisfied), and clear `__pycache__` after every revert.

- [ ] **Step 1: Write the harness**

A script that, for each row: asserts its search string occurs **exactly once**
in the target file, applies the replacement, runs the named test, records
pass/fail, reverts via `git checkout --`, and clears `__pycache__`. Assert
`count(old) == 1` — `_section(document, "audit")` appeared in both loaders last
session and two mutations silently never applied.

Note `os.fsync` appears **twice** in `audit.py` after Task 1, so rows 7 and 9
must name distinct surrounding context (`os.fsync(handle.fileno())` versus
`os.fsync(directory)`).

- [ ] **Step 2: Run all fifteen mutations**

| # | File | Mutation | Must redden |
|---|---|---|---|
| 1 | `audit.py` | `DEFAULT_DURABILITY = "fsync"` → `"flush"` | `test_audit_durability_defaults_to_the_safe_level` |
| 2 | `audit.py` | same | `test_the_control_plane_defaults_to_the_safe_level` |
| 3 | `loader.py` | `raise ConfigError(` in `_durability` → `return DEFAULT_DURABILITY` | `test_an_unrecognised_broker_durability_is_a_config_error` |
| 4 | `loader.py` | same | `test_an_unrecognised_control_durability_is_a_config_error` |
| 5 | `loader.py` | add an equality check across the two configs | `test_the_two_writers_may_choose_different_durability` |
| 6 | `audit.py` | delete the `ValueError` raise | `test_an_unrecognised_durability_is_refused_by_the_constructor` |
| 7 | `audit.py` | delete `os.fsync(handle.fileno())` | `test_an_append_fsyncs_the_log_before_returning` |
| 8 | `audit.py` | `if self.durability == "fsync":` → `if True:` | `test_flush_durability_does_not_fsync` |
| 9 | `audit.py` | delete the `os.fsync(directory)` block | `test_the_first_record_also_fsyncs_the_directory` |
| 10 | `audit.py` | `if seq == 0:` → `if True:` | `test_later_records_do_not_fsync_the_directory` |
| 11 | `audit.py` | wrap the file `fsync` in `try/except OSError: pass` | `test_a_failed_fsync_refuses_the_append_as_an_oserror` |
| 12 | `audit.py` | `fcntl.flock(handle.fileno(), fcntl.LOCK_UN)` before the `fsync` | `test_the_fsync_happens_while_the_lock_is_still_held` |
| 13 | `__main__.py` | drop `durability=config.audit_durability` | `test_the_broker_builds_its_audit_log_with_the_configured_durability` |
| 14 | `control_main.py` | drop `durability=config.audit_durability` | `test_the_control_plane_builds_...` |
| 15 | `demo/scenario/warden.toml` | `durability = "fsync"` → `"flush"` | `test_the_shipped_configs_name_the_safe_durability` |

- [ ] **Step 3: Read the failing test names out of pytest, not out of this table**

For each mutation, capture the actual `FAILED tests/...::name` lines. A row
whose named test does not appear is a **gap**, not a typo in the table — one
"GAP" last session was a guessed test name, and a mutation string can redden a
neighbouring test by collision. Record any mutation that reddens **nothing**
in the spec rather than papering over it.

- [ ] **Step 4: Re-run the five gates on the clean tree**

Confirm the tree is clean (`git status --short` empty) and all five gates pass
before declaring the work done.

- [ ] **Step 5: Update the spec with what the mutation pass found**

Add a *What the mutation pass found* section: the fifteen rows' outcomes, any
gap, and any mutation that reddened nothing. Amend the header's
"**Covers:** B2 only, in one commit" to two commits, with the reason. Commit.

---

## Self-Review

**Spec coverage.** Decisions 1–3 → Tasks 1 and 2. Decision 4 → Task 1 steps 5
and 6, pinned by row 12. Decision 5 → Task 1 step 5, rows 9 and 10. Decision 6 →
Task 1 step 5 (no code — the `OSError` propagates), pinned by row 11. Decision 7
→ Task 1 step 6's comment. Decision 8 → Task 1 step 6's comment correction.
Decision 9 → no code; pinned by the existing frozen-golden tests, which the
gates run. Decision 10 → Task 2 step 3, measured. *What changes* → Tasks 2–4.
All 15 proof rows → Task 5.

**Placeholders.** None: every code step carries the actual text. The two doc
steps (Task 4 steps 1–3) describe the edit rather than quoting the replacement
prose, which is deliberate — the surrounding paragraphs must be read at edit
time, and the *content* required is enumerated.

**Type consistency.** `DURABILITY_LEVELS` / `DEFAULT_DURABILITY` /
`self.durability` / `audit_durability` / `_durability(section, table)` are used
under exactly those names in every task that touches them.
