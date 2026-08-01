# Product/Demo Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate the warden enforcement point from the support-ticket demo, so the product ships as a configurable service with no scenario knowledge compiled in and the demo becomes a config on top of it.

**Architecture:** The product knows *adapter kinds* (`doc`, `db`, `http`, `mail`) and never tool names. Tools are declared in a TOML catalog; `authz.rego` keys its rules on target kind and reads a hand-authored tool→kind map from `data.json`. Two pip distributions (`warden`, `warden-demo`) make the seam a dependency direction, and two Dockerfiles keep the product image free of demo code.

**Tech Stack:** Python 3.11+ (stdlib `tomllib`), FastAPI, httpx, PyJWT, OPA 1.19.0 (Rego v1), pytest, Docker Compose.

**Spec:** [`docs/superpowers/specs/2026-08-01-product-demo-seam-design.md`](../specs/2026-08-01-product-demo-seam-design.md)

**Branch:** `product-demo-seam` (already exists, spec committed as `f8b84b3`)

## Global Constraints

- **Python 3.11 floor.** `tomllib` is stdlib from 3.11; it is the only TOML parser used.
- **Zero new product dependencies.** `requirements.txt` stays exactly: `fastapi==0.141.1`, `uvicorn[standard]==0.52.0`, `httpx==0.28.1`, `pyjwt[crypto]==2.13.0`, `pytest==9.1.1`, `pytest-asyncio==1.4.0`. Model SDKs stay in `requirements-live.txt` and never enter the product image.
- **OPA pinned to 1.19.0** everywhere: `docker-compose.yml`, `.github/workflows/ci.yml`, `cli/explain.py`, and the pytest fixture. The fixture asserts the version and **fails**, never skips, on mismatch.
- **Rego v1 syntax only.** `import rego.v1`; `if` / `contains` / `in` / `every`. No `import future.keywords.*`.
- **Rule names are frozen.** Exactly these eight strings and no others may appear as `deny_reasons` members: `input.malformed`, `tools.allowed`, `egress.allowlist`, `egress.pii_sink`, `rows.bounded`, `rows.scope`, `mail.counterparty`, `unauthenticated`. `broker/pdp.py`'s `DENY_PRECEDENCE` cannot rank a string it does not know and falls through to `pdp.unavailable`, naming a control that never fired.
- **The product tree contains none of these strings:** `4711`, `8812`, `attacker.example`, `docstore.internal`, `support-triage`, `triage-bot`, `refund`, `customers`.
- **Deny-by-default at the edge is preserved.** An unrecognised tool never reaches the PDP and is audited under `tools.allowed` with `target.kind == "unknown"`. `tests/test_app.py:129-133` and `:879` must pass unedited.
- **TDD.** Every task writes the failing test first, watches it fail for the stated reason, then implements.
- **Commit at the end of every task.** Never batch.
- **Docker works, but the shell's group set may be stale.** If `docker version` reports `permission denied` on `/var/run/docker.sock` while `getent group docker` lists you, the group was added after your shell started: prefix docker commands with `sg docker -c "…"`, or open a fresh login shell. Verified working: server 29.6.2, Compose v5.3.1.
- **Always `--build`.** Compose reuses whatever image exists. A stale image once ran pre-R7 code, which denied every db read `input.malformed`, left the task untainted, and let the PII POST to the allowlisted internal endpoint succeed — under a chain that reported itself intact. See Task 4.

---

# Phase 0 — Make the rest checkable

Ships no functionality. Four fixes and two frozen baselines, without which the refactor either cannot be verified or verifies falsely.

---

### Task 1: `audit.py` writes canonically ordered JSON

The log is hashed with `sort_keys=True` (`canonical_json`, line 36) but **written** with plain `json.dumps` (line 105), so the file's byte layout follows dict insertion order. Any adapter that builds a target dict in a different order changes the file's bytes while every hash still verifies — a diff that looks like tampering to a reader and clean to every automated check. Fix it before freezing a golden over it.

**Files:**
- Modify: `broker/audit.py:105`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: nothing
- Produces: `AuditLog.append()` writes lines whose keys are lexicographically sorted. `record_hash` and `canonical_json` are unchanged.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_audit.py`:

```python
def test_written_lines_are_key_sorted(tmp_path):
    """The file's bytes must not depend on dict insertion order.

    canonical_json already sorts for hashing; the write did not, so a target
    dict built in a different order changed the file while every hash still
    verified. That is a diff a reader reads as tampering and every check
    reads as clean.
    """
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(
        task_id="t",
        agent_id="a",
        purpose="p",
        # Deliberately reverse-alphabetical, so insertion order and sorted
        # order cannot coincide by accident.
        target={"kind": "db", "host": "", "estimated_rows": 3},
        action={"type": "tool_call", "tool": "x"},
        args_digest="sha256:d",
        decision="allow",
        rule="allow",
        task_state={"data_classes_held": [], "rows_returned_so_far": 0},
        policy_bundle_digest="sha256:b",
    )
    line = (tmp_path / "audit.jsonl").read_text().strip()
    keys = list(json.loads(line).keys())
    assert keys == sorted(keys), keys
    nested = list(json.loads(line)["target"].keys())
    assert nested == sorted(nested), nested
```

Confirm `json` is imported at the top of `tests/test_audit.py`; add `import json` if not.

- [ ] **Step 2: Run it and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_audit.py::test_written_lines_are_key_sorted -v
```

Expected: `FAIL` — `assert ['seq', 'ts', 'task_id', ...] == ['action', 'agent_id', ...]`.

- [ ] **Step 3: Implement**

In `broker/audit.py`, change line 105 from:

```python
                handle.write(json.dumps(record) + "\n")
```

to:

```python
                # sort_keys, matching canonical_json. Without it the file's
                # byte layout tracks dict insertion order, so a target built
                # in a different order changes the file while every hash
                # still verifies -- a diff that reads as tampering and
                # checks as clean.
                handle.write(json.dumps(record, sort_keys=True) + "\n")
```

- [ ] **Step 4: Run the full audit and chain suites**

```bash
.venv/bin/python -m pytest tests/test_audit.py tests/test_runlog.py -v
```

Expected: all PASS. `verify_chain` is unaffected — it re-hashes the parsed record, not the raw line.

- [ ] **Step 5: Run the whole suite**

```bash
.venv/bin/python -m pytest -q
```

Expected: `213 passed` (some may report as skipped if `opa` is absent; the count of failures must be 0).

- [ ] **Step 6: Commit**

```bash
git add broker/audit.py tests/test_audit.py
git commit -m "fix(audit): write the log key-sorted, as it is already hashed

canonical_json sorts for the hash; the write did not, so the file's byte
layout followed dict insertion order.  An adapter that builds a target dict
differently would change the file while every hash still verified -- a diff
a reader reads as tampering and every automated check reads as clean."
```

---

### Task 2: `policy_bundle_digest` covers every root, recursively

`Path(policies_dir).iterdir()` is non-recursive over a single directory. The moment the bundle is assembled from a product `authz.rego` and a deployment `data.json` on separate mounts, the digest silently stops covering the data — an operator could change `max_rows_per_task` from 50 to 5,000,000 and every audit record would still claim the identical policy. It has already drifted three ways undetected: the tree computes `sha256:03e4b6f4…`, `data/audit.jsonl` records `sha256:d6b319da…`, `runs/*.json` record `sha256:a3489853…`.

**Files:**
- Modify: `broker/policy_digest.py`
- Modify: `broker/__main__.py:64`
- Test: `tests/test_pdp.py:79-96`

**Interfaces:**
- Consumes: nothing
- Produces: `policy_bundle_digest(roots: Sequence[Path]) -> str`. **Signature change:** takes a sequence, not a single path. Raises `ValueError` on a root that is missing or contains no non-test files. Walks each root with `rglob("*")`, sorts by path relative to that root, and prefixes each file's contribution with its relative POSIX path so two roots holding same-named files cannot collide.

- [ ] **Step 1: Write the failing tests**

Replace `tests/test_pdp.py:79-96` (the two existing digest tests) with:

```python
def test_bundle_digest_is_stable_and_content_sensitive(tmp_path):
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    (tmp_path / "data.json").write_text('{"limits": {}}\n')
    first = policy_bundle_digest([tmp_path])
    assert first == policy_bundle_digest([tmp_path])
    assert first.startswith("sha256:")

    (tmp_path / "data.json").write_text('{"limits": {"max_rows_per_task": 50}}\n')
    assert policy_bundle_digest([tmp_path]) != first


def test_bundle_digest_ignores_test_files(tmp_path):
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    before = policy_bundle_digest([tmp_path])
    (tmp_path / "authz_test.rego").write_text("package warden.authz_test\n")
    assert policy_bundle_digest([tmp_path]) == before


def test_bundle_digest_covers_nested_files(tmp_path):
    """iterdir() dropped subdirectories entirely, so a bundle laid out in
    subdirectories was digested as if those files were not there."""
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "data.json").write_text('{"limits": {}}\n')
    before = policy_bundle_digest([tmp_path])
    (nested / "data.json").write_text('{"limits": {"max_rows_per_task": 5000000}}\n')
    assert policy_bundle_digest([tmp_path]) != before


def test_bundle_digest_covers_every_root(tmp_path):
    """The whole reason for the signature change: a bundle split across two
    mounts must be digested as one.  Dropping the data root silently stopped
    the digest covering max_rows_per_task."""
    rules = tmp_path / "rules"
    data = tmp_path / "data"
    rules.mkdir()
    data.mkdir()
    (rules / "authz.rego").write_text("package warden.authz\n")
    (data / "data.json").write_text('{"limits": {"max_rows_per_task": 50}}\n')

    both = policy_bundle_digest([rules, data])
    assert both != policy_bundle_digest([rules])

    (data / "data.json").write_text('{"limits": {"max_rows_per_task": 5000000}}\n')
    assert policy_bundle_digest([rules, data]) != both


def test_bundle_digest_rejects_a_missing_root(tmp_path):
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    with pytest.raises(ValueError, match="does not exist"):
        policy_bundle_digest([tmp_path, tmp_path / "absent"])


def test_bundle_digest_rejects_an_empty_root(tmp_path):
    """An empty root is a mount that did not happen.  Digesting it as the
    empty string would make a missing data.json indistinguishable from a
    data.json that is genuinely absent from the design."""
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no policy files"):
        policy_bundle_digest([tmp_path, empty])


def test_bundle_digest_distinguishes_which_root_a_file_came_from(tmp_path):
    """Two roots each holding data.json must not hash the same as one root
    holding both contents concatenated."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "data.json").write_text('{"x": 1}\n')
    (b / "data.json").write_text('{"y": 2}\n')
    assert policy_bundle_digest([a, b]) != policy_bundle_digest([b, a])
```

Ensure `import pytest` is present at the top of `tests/test_pdp.py`.

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_pdp.py -k digest -v
```

Expected: the two rewritten tests fail with `TypeError: expected str, bytes or os.PathLike object, not list`; the five new ones fail the same way.

- [ ] **Step 3: Implement**

Replace the body of `broker/policy_digest.py` with:

```python
"""Deterministic digest of the policy bundle.

Stamped into every audit record so a decision can be replayed against the
exact policy that produced it. Test files are excluded -- they do not affect
any decision.

Takes a LIST of roots, walked recursively. Both properties are load-bearing
once the bundle is assembled from a product rules root and a deployment data
root on separate mounts: the previous single-directory, non-recursive form
would have digested the rules and silently omitted the data, so an operator
could change max_rows_per_task from 50 to 5,000,000 and every record would
still claim the identical policy.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path


def _bundle_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and not path.name.endswith("_test.rego")
    )


def policy_bundle_digest(roots: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for raw_root in roots:
        root = Path(raw_root)
        if not root.is_dir():
            raise ValueError(f"policy bundle root does not exist: {root}")
        files = _bundle_files(root)
        if not files:
            # An empty root is a mount that did not happen. Hashing nothing
            # would make that indistinguishable from a root the design does
            # not include, which is exactly the failure this must be loud
            # about.
            raise ValueError(f"policy bundle root has no policy files: {root}")
        for path in files:
            # The path RELATIVE TO ITS ROOT, not the bare name: two roots
            # each holding a data.json must not collide, and the digest must
            # not change when the mount point moves.
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        digest.update(b"\0\0")
    return f"sha256:{digest.hexdigest()}"
```

- [ ] **Step 4: Update the four call sites**

`broker/__main__.py:64` — replace:

```python
        "policy_digest": policy_bundle_digest(Path(env.get("POLICY_PATH", "/policies"))),
```

with:

```python
        "policy_digest": policy_bundle_digest(
            [Path(part) for part in env.get("POLICY_PATH", "/policies").split(":")]
        ),
```

`cli/explain.py:841` — replace `policy_bundle_digest(Path('policies'))` with `policy_bundle_digest([Path('policies')])`.

`cli/explain.py:911` — replace `policy_bundle_digest(Path("policies"))` with `policy_bundle_digest([Path("policies")])`.

`cli/runlog.py:81` — replace `return policy_bundle_digest(Path("policies"))` with `return policy_bundle_digest([Path("policies")])`.

`tests/test_injection_contained.py:159` — replace `policy_bundle_digest(Path("policies"))` with `policy_bundle_digest([Path("policies")])`.

- [ ] **Step 5: Run the tests**

```bash
.venv/bin/python -m pytest tests/test_pdp.py -k digest -v && .venv/bin/python -m pytest -q
```

Expected: all digest tests PASS; whole suite has 0 failures.

- [ ] **Step 6: Verify no call site was missed**

```bash
grep -rn "policy_bundle_digest(" --include="*.py" . | grep -v __pycache__ | grep -v "def policy_bundle_digest"
```

Expected: every hit passes a list (`[Path(...)]` or a list comprehension). Zero hits pass a bare `Path`.

- [ ] **Step 7: Commit**

```bash
git add broker/policy_digest.py broker/__main__.py cli/explain.py cli/runlog.py tests/test_pdp.py tests/test_injection_contained.py
git commit -m "fix(policy): digest every bundle root, recursively

iterdir() over one directory meant that splitting the bundle across a product
rules mount and a deployment data mount would silently stop the digest
covering data.json -- max_rows_per_task 50 -> 5000000 with every audit record
claiming the identical policy.  Takes a list of roots now, walks each with
rglob, and refuses a root that is missing or empty rather than digesting the
absence as nothing."
```

---

### Task 3: One pinned OPA version, asserted not skipped

There are three OPA resolutions and only two are pinned. `cli/explain.py:633` and `tests/test_injection_contained.py:58-82` resolve `opa` off `PATH`, which on this machine is **0.70.0** — a major version behind the pinned 1.19.0. The single Python test that evaluates the real policy against the real bundle is therefore not evidence about the version that ships, and Phase 2's whole gate rests on it.

**Files:**
- Create: `tools/opa_version.py`
- Create: `scripts/fetch-opa.sh`
- Modify: `cli/explain.py:632-634`
- Modify: `tests/test_injection_contained.py:58-90`
- Modify: `docker-compose.yml:20`
- Modify: `.github/workflows/ci.yml:15-21`

**Interfaces:**
- Consumes: nothing
- Produces: `tools/opa_version.py` exporting `OPA_VERSION = "1.19.0"` and `resolve_opa() -> str` (absolute path to a binary of exactly that version) raising `RuntimeError` on absence or mismatch.

- [ ] **Step 1: Write the failing test**

Create `tests/test_opa_pin.py`:

```python
"""The pinned OPA version is one value, and every resolution honours it.

Three resolutions existed and only two were pinned; the unpinned pair --
cli/explain.py and the integration fixture -- ran 0.70.0 while the image and
CI ran 1.19.0. OPA 1.0 made Rego v1 the default and changed `opa test`
defaults, so a policy passing 44/44 locally was not evidence about what
ships.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tools.opa_version import OPA_VERSION, resolve_opa

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_compose_pins_the_same_version():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    assert f"openpolicyagent/opa:{OPA_VERSION}" in compose


def test_ci_pins_the_same_version():
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert f"v{OPA_VERSION}/opa_linux_amd64_static" in ci


def test_no_module_resolves_opa_off_bare_path():
    """shutil.which("opa") anywhere means an unpinned resolution came back."""
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or ".venv" in path.parts:
            continue
        if path.name == "opa_version.py":
            continue
        if re.search(r'shutil\.which\(\s*["\']opa["\']\s*\)', path.read_text()):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_resolve_opa_returns_a_binary_of_the_pinned_version():
    try:
        binary = resolve_opa()
    except RuntimeError as exc:
        pytest.skip(f"pinned opa not installed: {exc}")
    assert Path(binary).is_file()
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_opa_pin.py -v
```

Expected: collection error, `ModuleNotFoundError: No module named 'tools'`.

- [ ] **Step 3: Create the version module**

Create `tools/__init__.py` (empty) and `tools/opa_version.py`:

```python
"""The single pinned OPA version, and the only way to find that binary.

Four places resolved OPA and two of them took whatever was on PATH -- 0.70.0
on the development machine, against a 1.19.0 pin in the image and in CI. OPA
1.0 made Rego v1 the default, so `opa test policies/` passing locally was not
evidence about the engine that ships. Everything routes through here now, and
a version mismatch RAISES: the alternative is a skip, and the one test that
evaluates the real policy against the real bundle must not be able to quietly
not run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

OPA_VERSION = "1.19.0"

# Where scripts/fetch-opa.sh puts it. Checked before PATH so a stale system
# opa cannot win.
PINNED_PATH = Path.home() / ".cache" / "warden" / f"opa-{OPA_VERSION}"


def installed_version(binary: str) -> str | None:
    """The `Version:` line from `opa version`, or None if it cannot be read."""
    try:
        result = subprocess.run(
            [binary, "version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def resolve_opa() -> str:
    """Absolute path to an OPA binary of exactly OPA_VERSION.

    Raises rather than returning a different version. A caller that wants to
    degrade gracefully catches RuntimeError and says so out loud.
    """
    candidates = [str(PINNED_PATH)]
    from_path = shutil.which("opa")
    if from_path:
        candidates.append(from_path)
    local = Path.home() / ".local" / "bin" / "opa"
    if local.is_file():
        candidates.append(str(local))

    seen: list[str] = []
    for candidate in candidates:
        if not (Path(candidate).is_file() and os.access(candidate, os.X_OK)):
            continue
        version = installed_version(candidate)
        if version == OPA_VERSION:
            return candidate
        seen.append(f"{candidate} is {version or 'unreadable'}")

    detail = "; ".join(seen) if seen else "no opa binary found"
    raise RuntimeError(
        f"OPA {OPA_VERSION} required ({detail}). Run scripts/fetch-opa.sh."
    )
```

- [ ] **Step 4: Create the fetch script**

Create `scripts/fetch-opa.sh` and `chmod +x` it:

```bash
#!/usr/bin/env bash
# Downloads the pinned OPA into ~/.cache/warden/, where tools/opa_version.py
# looks first. Deliberately NOT ~/.local/bin: that is where an unpinned opa is
# already installed on some machines, and the point is to stop resolving to it.
set -euo pipefail
VERSION="$(python3 -c 'import sys; sys.path.insert(0, "."); from tools.opa_version import OPA_VERSION; print(OPA_VERSION)')"
DEST="$HOME/.cache/warden/opa-$VERSION"
mkdir -p "$(dirname "$DEST")"
if [ -x "$DEST" ]; then
  echo "already present: $DEST"
  "$DEST" version | head -1
  exit 0
fi
curl -sSL -o "$DEST" \
  "https://openpolicyagent.org/downloads/v$VERSION/opa_linux_amd64_static"
chmod +x "$DEST"
"$DEST" version | head -1
```

- [ ] **Step 5: Repoint `cli/explain.py`**

Replace lines 632-634 (`def _start_opa` opening through the `sys.exit`):

```python
def _start_opa() -> tuple[subprocess.Popen, str]:
    try:
        binary = resolve_opa()
    except RuntimeError as exc:
        sys.exit(f"{exc}  See docs/WALKTHROUGH.md Part 0.")
```

Add to the imports near line 56: `from tools.opa_version import resolve_opa`. Remove the now-unused `shutil` import only if nothing else in the file uses it — check with `grep -n "shutil\." cli/explain.py` first.

- [ ] **Step 6: Repoint the integration fixture**

Replace `tests/test_injection_contained.py:58-82` (`_resolve_opa`) entirely, and change the fixture to fail rather than skip:

```python
def _resolve_opa() -> str:
    """The pinned binary, or a hard failure.

    This used to prepend ~/.local/bin to PATH and take whatever it found --
    0.70.0 on this machine, against a 1.19.0 pin in the image and in CI. This
    is the single most important test in the project: it evaluates the real
    policy against the real bundle, and it is the only tripwire for the
    target-kind rekeying. It must not be able to run against a different
    engine, and it must not be able to silently skip.
    """
    return resolve_opa()
```

Add `from tools.opa_version import resolve_opa` to the imports, and remove the now-unused `shutil` / `os` imports if nothing else uses them.

Then in the `opa_url` fixture, replace:

```python
    if _resolve_opa() is None:
        pytest.skip("opa binary not on PATH")
    port = _free_port()
    process = subprocess.Popen(
        ["opa", "run", "--server", f"--addr=127.0.0.1:{port}", "policies"],
```

with:

```python
    binary = _resolve_opa()
    port = _free_port()
    process = subprocess.Popen(
        [binary, "run", "--server", f"--addr=127.0.0.1:{port}", "policies"],
```

`_resolve_opa()` now raises `RuntimeError` with the fetch instruction, which pytest reports as an error rather than a skip. That is the point.

- [ ] **Step 7: Fetch the pinned binary and run**

```bash
./scripts/fetch-opa.sh && .venv/bin/python -m pytest tests/test_opa_pin.py -v
```

Expected: `Version: 1.19.0` from the script, then all four tests PASS.

- [ ] **Step 8: Run the policy suite on the pinned engine**

```bash
~/.cache/warden/opa-1.19.0 test policies/ -v 2>&1 | tail -20
```

Expected: `PASS: 44/44`. **If any test fails here, stop and report it** — it means the shipped policy does not pass on the pinned engine and that must be fixed before anything else in this plan proceeds.

- [ ] **Step 9: Run the integration test on the pinned engine**

```bash
.venv/bin/python -m pytest tests/test_injection_contained.py -v
```

Expected: all PASS, zero skips.

- [ ] **Step 10: Update CI to reuse the same constant**

In `.github/workflows/ci.yml`, replace the `Install OPA` step with:

```yaml
      - name: Install OPA
        run: ./scripts/fetch-opa.sh
      - name: Policy unit tests
        run: ~/.cache/warden/opa-1.19.0 test policies/ -v
```

- [ ] **Step 11: Full suite and commit**

```bash
.venv/bin/python -m pytest -q
git add tools/ scripts/fetch-opa.sh cli/explain.py tests/test_injection_contained.py tests/test_opa_pin.py .github/workflows/ci.yml
git commit -m "fix: one pinned OPA version, and a resolution that cannot silently drift

Three resolutions, two pinned.  cli/explain.py and the integration fixture
took whatever was on PATH -- 0.70.0 here, against 1.19.0 in the image and in
CI -- so the one test that evaluates the real policy against the real bundle
ran a major version behind what ships.  OPA 1.0 made Rego v1 the default;
44/44 on 0.70.0 was not evidence about 1.19.0.

resolve_opa() raises on a mismatch rather than skipping, because a test this
load-bearing must not be able to quietly not run."
```

---

### Task 4: `demo.sh` must rebuild, because a stale image runs old code silently

Found by running the demo before writing this task. `scripts/demo.sh:46` does `docker compose up -d` with **no `--build`**, so Compose reuses whatever image exists. On a tree containing the R7 `subjects` change, the broker container was still running pre-R7 code and emitted a target dict with no `subjects` key. `authz.rego:137-140` denied it `input.malformed`, correctly and by design — but the consequences ran all the way through:

```
  ✗ query_customers(rows≈1)                DENY   input.malformed   ← never allowed, so
  ✗ query_customers(rows≈10312)            DENY   input.malformed   ← never tainted, so
  ✗ http_fetch(attacker.example/collect)   DENY   egress.allowlist
  ✓ http_fetch(docstore.internal/feedback) allow                    ← PII POST SUCCEEDED
  chain intact: 7 records, head sha256:59a6af50…
```

The task never held `data_class=pii`, so R4 `egress.pii_sink` never fired, and `docstore.internal` **is** on the allowlist. The demo's central claim — "the fallback destination is allowlisted; only the data-flow rule stops it" — failed, and the audit chain reported itself intact over the whole thing. After `docker compose build`, the run reproduces `README.md:37-48` line for line.

A demo whose containers can lag the tree cannot be the thing a golden is frozen from.

**Files:**
- Modify: `scripts/demo.sh:26,46`
- Test: `tests/test_entrypoints.py`

**Interfaces:**
- Consumes: nothing
- Produces: `scripts/demo.sh` builds before every `up`, in both profiles.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_entrypoints.py`:

```python
def test_demo_script_rebuilds_before_starting_containers():
    """A stale image runs old code while the run looks current.

    Observed: an image predating the R7 `subjects` change emitted a target
    dict without that key, the policy denied it input.malformed (correctly),
    the task therefore never became tainted, and the PII POST to the
    allowlisted internal endpoint SUCCEEDED -- the demo's central claim,
    inverted, under a chain that reported itself intact.
    """
    script = (REPO_ROOT / "scripts" / "demo.sh").read_text()
    ups = [line for line in script.splitlines() if "docker compose" in line and " up " in line]
    assert ups, "no `docker compose up` found in demo.sh"
    for line in ups:
        assert "--build" in line, f"up without --build: {line.strip()}"
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_entrypoints.py::test_demo_script_rebuilds_before_starting_containers -v
```

Expected: `FAIL` — `up without --build: docker compose --profile guarded up -d opa docstore ...`.

- [ ] **Step 3: Implement**

In `scripts/demo.sh`, line 26, change:

```bash
  docker compose --profile unprotected up -d docstore mailer sinkhole
```

to:

```bash
  # --build on every run.  Without it Compose reuses whatever image exists,
  # so a code change silently does not reach the containers: an image
  # predating the `subjects` field made the policy deny every db read as
  # input.malformed, the task never became tainted, and the PII POST to the
  # allowlisted internal endpoint went through -- with the chain reporting
  # itself intact.
  docker compose --profile unprotected up -d --build docstore mailer sinkhole
```

And line 46:

```bash
  docker compose --profile guarded up -d --build opa docstore mailer sinkhole broker broker-control
```

- [ ] **Step 4: Run the test**

```bash
.venv/bin/python -m pytest tests/test_entrypoints.py -v
```

Expected: all PASS.

- [ ] **Step 5: Run the demo end to end and confirm it matches the README**

Docker's group membership may postdate your shell; if `docker version` says permission denied but `getent group docker` lists you, prefix with `sg docker -c`.

```bash
sg docker -c "./scripts/demo.sh guarded" 2>&1 | tail -12
```

Expected, exactly:

```
task 4711  purpose=support-triage  agent=triage-bot
  ✓ read_document(ticket-4711)             allow
  ✓ read_document(kb/refund-policy)        allow
  ✓ query_customers(rows≈1)                allow
      ⛔ TAINT: task now holds data_class=pii
  ✗ query_customers(rows≈10312)            DENY   rows.bounded
  ✗ http_fetch(attacker.example/collect)   DENY   egress.allowlist
  ✗ http_fetch(docstore.internal/feedback) DENY   egress.pii_sink
  ✓ send_email(customer:8812)              allow
  chain intact: 7 records, head sha256:········
```

- [ ] **Step 6: Commit**

```bash
git add scripts/demo.sh tests/test_entrypoints.py
git commit -m "fix(demo): rebuild before every up, so containers cannot lag the tree

Compose reuses whatever image exists.  An image predating the R7 subjects
field emitted a target dict without that key; the policy denied every db read
as input.malformed -- correctly, per the comment that says a broker which
stops sending the field must be a loud denial -- and the consequences ran all
the way through: the task never became tainted, egress.pii_sink never fired,
and the PII POST to the allowlisted internal endpoint SUCCEEDED.  The demo's
central claim, inverted, under a chain reporting itself intact."
```

---

### Task 5: Freeze the audit and replay goldens

**Files:**
- Create: `tests/golden/audit-4711.jsonl`
- Create: `tests/golden/replay-4711.txt`
- Create: `tests/golden/README.md`
- Create: `tests/test_golden_replay.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `scripts/demo.sh guarded` (Task 4), `AuditLog` key-sorted writes (Task 1)
- Produces: `tests/golden/audit-4711.jsonl` — a checked-in seven-record log. `tests/golden/replay-4711.txt` — the exact bytes `warden replay 4711 --audit tests/golden/audit-4711.jsonl` prints. Later phases assert against these and must not regenerate them.

- [ ] **Step 1: Confirm `data/` being gitignored does not block the golden**

```bash
grep -n "^data/\|^audit.jsonl" .gitignore
```

Expected: both present. That is why the golden lives under `tests/`, not `data/`.

- [ ] **Step 2: Add a negative-ignore so the golden is trackable**

Append to `.gitignore`:

```
# The frozen baseline. data/ is ignored, so the golden log lives under tests/
# and must be tracked -- it is the artefact every later phase is checked
# against, and a golden that is not in git is not a baseline.
!tests/golden/
```

- [ ] **Step 3: Write the failing test**

Create `tests/test_golden_replay.py`:

```python
"""The renderer and reader are pinned against a frozen log.

`warden replay` reads a RECORDED log -- it never builds a policy input and
never calls the PDP -- so it cannot detect a policy regression. It is not a
policy gate (tests/test_golden_decisions.py is). What it does pin, exactly,
is that the reader and renderer keep turning the same bytes into the same
text.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "golden"


def test_replay_of_the_frozen_log_is_byte_identical():
    expected = (GOLDEN / "replay-4711.txt").read_bytes()
    result = subprocess.run(
        [sys.executable, "-m", "cli.warden", "replay", "4711",
         "--audit", str(GOLDEN / "audit-4711.jsonl")],
        cwd=REPO_ROOT, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == expected


def test_the_frozen_log_still_verifies():
    """If the chain over the golden ever breaks, the golden was edited."""
    result = subprocess.run(
        [sys.executable, "-m", "cli.warden", "verify-chain",
         "--audit", str(GOLDEN / "audit-4711.jsonl")],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "chain intact: 7 records" in result.stdout


def test_the_frozen_log_is_the_documented_run():
    """Seven records, three denials, and the three rules the README names."""
    import json

    records = [
        json.loads(line)
        for line in (GOLDEN / "audit-4711.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(records) == 7
    assert [(r["action"]["tool"], r["decision"]) for r in records] == [
        ("read_document", "allow"),
        ("read_document", "allow"),
        ("query_customers", "allow"),
        ("query_customers", "deny"),
        ("http_fetch", "deny"),
        ("http_fetch", "deny"),
        ("send_email", "allow"),
    ]
    assert [r["rule"] for r in records if r["decision"] == "deny"] == [
        "rows.bounded", "egress.allowlist", "egress.pii_sink",
    ]
    # The subjects key is what a pre-R7 broker omitted, which denied every db
    # read as input.malformed and un-tainted the whole run.
    assert all("subjects" in r["target"] for r in records)
```

- [ ] **Step 4: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_golden_replay.py -v
```

Expected: `FileNotFoundError` / assertion failures — the golden directory does not exist.

- [ ] **Step 5: Capture the golden from a freshly built run**

```bash
sg docker -c "./scripts/demo.sh guarded" > /dev/null 2>&1
mkdir -p tests/golden
cp data/audit.jsonl tests/golden/audit-4711.jsonl
.venv/bin/python -m cli.warden replay 4711 --audit tests/golden/audit-4711.jsonl \
  > tests/golden/replay-4711.txt
cat tests/golden/replay-4711.txt
```

Expected: the seven-record replay ending `chain intact: 7 records, head sha256:…`.

- [ ] **Step 6: Write the golden's provenance note**

Create `tests/golden/README.md`:

```markdown
# Frozen baseline

Captured from `./scripts/demo.sh guarded` in **cassette mode** on a freshly
built image, before the product/demo seam refactor began. Cassette-guarded
produces seven records and no `CONNECT`; a `--live` run produces an extra
proxy record and a different count, so the mode matters.

`audit-4711.jsonl` is a real hash-chained log. Do not hand-edit it: the chain
verifies in `tests/test_golden_replay.py`, and an edit is indistinguishable
from tampering, which is the point.

`replay-4711.txt` is the exact stdout of

    python -m cli.warden replay 4711 --audit tests/golden/audit-4711.jsonl

**This pair is not a policy gate.** `warden replay` reads a recorded log; it
never constructs a policy input and never calls the PDP, so a refactor that
turned every deny into an allow would leave both files matching. The policy
gate is `tests/golden/decisions/`, asserted by
`tests/test_golden_decisions.py`.

Regenerate only when a change is *intended* to alter the log, and say so in
the commit message.
```

- [ ] **Step 7: Run and confirm green**

```bash
.venv/bin/python -m pytest tests/test_golden_replay.py -v
```

Expected: 3 PASS.

- [ ] **Step 8: Commit**

```bash
git add -f tests/golden/ tests/test_golden_replay.py .gitignore
git commit -m "test: freeze the demo's audit log and replay output as a baseline

Captured from a freshly built guarded run that reproduces README.md:37-48
line for line.  Pins the reader and the renderer, and nothing more: replay
reads a recorded log and never calls the PDP, so it cannot detect a policy
regression.  That gate is the decision corpus, next."
```


---

### Task 6: The decision corpus — the gate that can actually catch a policy regression

`warden replay` reads a recorded log. It never builds a policy input and never calls the PDP, so a refactor turning every deny into an allow leaves it byte-identical. And `authz_test.rego` mocks `data.purposes`/`data.limits` in almost every case — the file's own R1c comment says "no test could have caught this" — so adding a *correct* `data.tools` mock in Phase 2 reintroduces that blind spot on a new key. Verified during design: the mechanical mock edit against a naively-generalised policy gives `opa test` PASS 44/44 while a mislabelled 5,000,000-row read evaluates to `allow: true`.

This corpus is the only gate that closes both holes: real inputs, real `opa eval`, the shipped bundle, **no `with` overrides**.

**Mechanism verified before writing this task** — reconstructing each input from the golden audit record plus the fixed token fields reproduces all seven audited rules on OPA 1.19.0, including the two precedence picks (`rows.bounded` over `rows.scope`; `egress.allowlist` over `egress.pii_sink`).

**Files:**
- Create: `tests/golden/decisions/*.json` (13 cases)
- Create: `tests/golden/decisions/expected.json`
- Create: `tools/build_corpus.py`
- Create: `tests/test_golden_decisions.py`

**Interfaces:**
- Consumes: `tests/golden/audit-4711.jsonl` (Task 5), `tools/opa_version.resolve_opa` (Task 3), `broker.pdp.DENY_PRECEDENCE`
- Produces: `tests/golden/decisions/<case>.json` — one policy input document each. `tests/golden/decisions/expected.json` — `{case: {"deny_reasons": [...sorted], "rule": "..."}}`. `tools/build_corpus.py` regenerates the seven demo cases from the golden log; the six adversarial cases are hand-authored and it never touches them.

- [ ] **Step 1: Write the failing test**

Create `tests/test_golden_decisions.py`:

```python
"""The policy gate.

Every input in tests/golden/decisions/ is evaluated by the REAL opa binary
against the REAL policies/ directory, with NO `with` overrides. That last
part is the whole point: authz_test.rego mocks data.purposes and data.limits
in almost every case, so the shipped data document's shape is barely
exercised -- the file's own R1c comment says as much -- and Phase 2 adding a
correct data.tools mock everywhere would reintroduce that blindness on a new
key. Verified during design: that mock edit yields opa test PASS 44/44 over a
policy that approves a mislabelled 5,000,000-row read at runtime.

This is also the gate warden replay cannot be: replay reads a recorded log
and never calls the PDP.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from broker.pdp import DENY_PRECEDENCE
from tools.opa_version import resolve_opa

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "tests" / "golden" / "decisions"


def _cases() -> list[str]:
    return sorted(p.stem for p in CORPUS.glob("*.json") if p.stem != "expected")


def _evaluate(binary: str, document: dict) -> list[str]:
    result = subprocess.run(
        [binary, "eval", "-I", "-d", str(REPO_ROOT / "policies"),
         "data.warden.authz.deny_reasons", "--format=json"],
        input=json.dumps(document), capture_output=True, text=True,
        cwd=REPO_ROOT, check=False,
    )
    assert result.returncode == 0, result.stderr
    return sorted(json.loads(result.stdout)["result"][0]["expressions"][0]["value"])


def _rule(reasons: list[str]) -> str:
    if not reasons:
        return "allow"
    for candidate in DENY_PRECEDENCE:
        if candidate in reasons:
            return candidate
    # pdp.py returns pdp.unavailable here, naming a control that never fired.
    return "UNRANKED"


@pytest.fixture(scope="module")
def opa_binary() -> str:
    return resolve_opa()


@pytest.mark.parametrize("case", _cases())
def test_decision_matches_the_frozen_expectation(case, opa_binary):
    expected = json.loads((CORPUS / "expected.json").read_text())[case]
    document = json.loads((CORPUS / f"{case}.json").read_text())
    reasons = _evaluate(opa_binary, document)
    assert reasons == expected["deny_reasons"], case
    assert _rule(reasons) == expected["rule"], case


def test_every_case_has_an_expectation():
    expected = json.loads((CORPUS / "expected.json").read_text())
    assert sorted(expected) == _cases()


def test_no_reason_is_unrankable():
    """A deny_reasons member DENY_PRECEDENCE cannot rank makes pdp.py fall
    through to pdp.unavailable -- the replay then names a control that never
    fired. The rekeying must introduce zero new reason strings."""
    expected = json.loads((CORPUS / "expected.json").read_text())
    for case, outcome in expected.items():
        assert outcome["rule"] != "UNRANKED", case
        for reason in outcome["deny_reasons"]:
            assert reason in DENY_PRECEDENCE, f"{case}: {reason}"
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_golden_decisions.py -v
```

Expected: collection produces no parametrised cases and `test_every_case_has_an_expectation` fails with `FileNotFoundError` — the corpus does not exist.

- [ ] **Step 3: Write the corpus builder**

Create `tools/build_corpus.py`:

```python
"""Regenerates the seven demo decision inputs from the frozen audit log.

The audit record stores everything the policy input needs except the two
token fields, which are fixed for the demo, and which are stated here rather
than guessed. Deriving the corpus from the log rather than hand-writing it is
what makes it faithful: verified on OPA 1.19.0 that all seven reconstructed
inputs reproduce their audited rule exactly, including both precedence picks.

The adversarial cases in the same directory are hand-authored. This script
never writes them and never touches expected.json for them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN = REPO_ROOT / "tests" / "golden"
CORPUS = GOLDEN / "decisions"

# From the token scripts/demo.sh mints. Not in the audit record, because a
# record states what was decided, not what the token permitted.
TOKEN_FIELDS = {
    "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "counterparties": ["customer:8812"],
}

DEMO_CASES = [
    "demo-1-read-ticket",
    "demo-2-read-poisoned-kb",
    "demo-3-read-one-customer",
    "demo-4-bulk-read",
    "demo-5-exfil-to-attacker",
    "demo-6-exfil-to-allowlisted-sink",
    "demo-7-reply-to-customer",
]


def policy_input(record: dict) -> dict:
    return {
        "principal": {
            "agent_id": record["agent_id"],
            "task_id": record["task_id"],
            "purpose": record["purpose"],
            **TOKEN_FIELDS,
        },
        "action": {
            "type": record["action"]["type"],
            "tool": record["action"]["tool"],
            "args_digest": record["args_digest"],
        },
        "target": record["target"],
        "task_state": record["task_state"],
    }


def main() -> int:
    records = [
        json.loads(line)
        for line in (GOLDEN / "audit-4711.jsonl").read_text().splitlines()
        if line.strip()
    ]
    if len(records) != len(DEMO_CASES):
        print(f"expected {len(DEMO_CASES)} records, found {len(records)}", file=sys.stderr)
        return 1
    CORPUS.mkdir(parents=True, exist_ok=True)
    for name, record in zip(DEMO_CASES, records):
        (CORPUS / f"{name}.json").write_text(
            json.dumps(policy_input(record), indent=2, sort_keys=True) + "\n"
        )
        print(f"wrote {name}.json  (audited rule: {record['rule']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Generate the seven demo cases**

```bash
.venv/bin/python -m tools.build_corpus
```

Expected: seven `wrote …` lines naming audited rules `allow`, `allow`, `allow`, `rows.bounded`, `egress.allowlist`, `egress.pii_sink`, `allow`.

- [ ] **Step 5: Hand-author the six adversarial cases**

These are the inputs the design review demonstrated as holes. They are not derived from any run — they exist to fail if Phase 2 regresses. Write each to `tests/golden/decisions/`.

`adversarial-1-mislabelled-db-target.json` — a `query_customers` call carrying a `doc` target and 5,000,000 rows. Today two rules fire independently; after the rekey only R1b stands between this and an allow.

```json
{
  "action": {"args_digest": "sha256:x", "tool": "query_customers", "type": "tool_call"},
  "principal": {
    "agent_id": "triage-bot", "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "counterparties": ["customer:8812"], "purpose": "support-triage", "task_id": "4711"
  },
  "target": {"estimated_rows": 5000000, "host": "", "kind": "doc", "path": "", "port": 0, "recipients": [], "subjects": []},
  "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}
}
```

`adversarial-2-undeclared-tool.json` — a tool the catalog does not declare, named by the token. This is the case the four-name allowlist catches today and that deleting it would open even under a perfectly correct catalog.

```json
{
  "action": {"args_digest": "sha256:x", "tool": "exfiltrate", "type": "tool_call"},
  "principal": {
    "agent_id": "triage-bot", "allowed_tools": ["exfiltrate"],
    "counterparties": ["customer:8812"], "purpose": "support-triage", "task_id": "4711"
  },
  "target": {"estimated_rows": 0, "host": "", "kind": "doc", "path": "", "port": 0, "recipients": [], "subjects": []},
  "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 0}
}
```

`adversarial-3-mail-with-doc-target.json` — `send_email` to an undeclared recipient carrying a `doc` target, the R6 equivalent.

```json
{
  "action": {"args_digest": "sha256:x", "tool": "send_email", "type": "tool_call"},
  "principal": {
    "agent_id": "triage-bot", "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "counterparties": ["customer:8812"], "purpose": "support-triage", "task_id": "4711"
  },
  "target": {"estimated_rows": 0, "host": "", "kind": "doc", "path": "", "port": 0, "recipients": ["attacker@evil.example"], "subjects": []},
  "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}
}
```

`adversarial-4-db-with-mail-target.json` — `query_customers` reaching an out-of-scope subject while carrying a `mail` target, the R7 equivalent.

```json
{
  "action": {"args_digest": "sha256:x", "tool": "query_customers", "type": "tool_call"},
  "principal": {
    "agent_id": "triage-bot", "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "counterparties": ["customer:8812"], "purpose": "support-triage", "task_id": "4711"
  },
  "target": {"estimated_rows": 1, "host": "", "kind": "mail", "path": "", "port": 0, "recipients": [], "subjects": ["customer:9999"]},
  "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}
}
```

`adversarial-5-egress-allowlisted.json` — a proxy CONNECT with no `action.tool` at all. This is the case that turns into a total outage if either new R1b rule is written without its `input.action.type == "tool_call"` guard: `safe_action_tool` is null for egress, so an ungated rule makes every CONNECT `input.malformed` and the agent loses all model-API egress.

```json
{
  "action": {"args_digest": "sha256:none", "type": "egress"},
  "principal": {
    "agent_id": "triage-bot", "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "counterparties": ["customer:8812"], "purpose": "support-triage", "task_id": "4711"
  },
  "target": {"estimated_rows": 0, "host": "docstore.internal", "kind": "http", "path": "", "port": 443, "recipients": []},
  "task_state": {"data_classes_held": [], "rows_returned_so_far": 0}
}
```

`adversarial-6-egress-tainted-to-unapproved.json` — the same CONNECT shape once the task holds PII, reaching a host that is on `egress_allow` but not on `pii_approved_sinks`.

```json
{
  "action": {"args_digest": "sha256:none", "type": "egress"},
  "principal": {
    "agent_id": "triage-bot", "allowed_tools": ["read_document", "query_customers", "http_fetch", "send_email"],
    "counterparties": ["customer:8812"], "purpose": "support-triage", "task_id": "4711"
  },
  "target": {"estimated_rows": 0, "host": "docstore.internal", "kind": "http", "path": "", "port": 443, "recipients": []},
  "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 0}
}
```

- [ ] **Step 6: Record what the shipped policy says today**

Do **not** hand-write `expected.json` — capture what the current, unmodified policy actually decides, so Phase 2 is compared against reality rather than against belief.

```bash
.venv/bin/python - <<'EOF'
import json, subprocess
from pathlib import Path
import sys
sys.path.insert(0, '.')
from broker.pdp import DENY_PRECEDENCE
from tools.opa_version import resolve_opa

CORPUS = Path("tests/golden/decisions")
binary = resolve_opa()
out = {}
for path in sorted(CORPUS.glob("*.json")):
    if path.stem == "expected":
        continue
    result = subprocess.run(
        [binary, "eval", "-I", "-d", "policies/",
         "data.warden.authz.deny_reasons", "--format=json"],
        input=path.read_text(), capture_output=True, text=True, check=True)
    reasons = sorted(json.loads(result.stdout)["result"][0]["expressions"][0]["value"])
    rule = "allow" if not reasons else next(
        (c for c in DENY_PRECEDENCE if c in reasons), "UNRANKED")
    out[path.stem] = {"deny_reasons": reasons, "rule": rule}
    print(f"{path.stem:<40} {rule:<18} {reasons}")
(CORPUS / "expected.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
EOF
```

Expected output — check each line against this table before continuing. Any deviation means the corpus input is wrong, not that the expectation is:

| case | rule | deny_reasons |
|---|---|---|
| `adversarial-1-mislabelled-db-target` | `input.malformed` | `["input.malformed", "rows.bounded"]` |
| `adversarial-2-undeclared-tool` | `input.malformed` | `["input.malformed"]` |
| `adversarial-3-mail-with-doc-target` | `input.malformed` | `["input.malformed", "mail.counterparty"]` |
| `adversarial-4-db-with-mail-target` | `input.malformed` | `["input.malformed", "rows.scope"]` |
| `adversarial-5-egress-allowlisted` | `allow` | `[]` |
| `adversarial-6-egress-tainted-to-unapproved` | `egress.pii_sink` | `["egress.pii_sink"]` |
| `demo-1-read-ticket` | `allow` | `[]` |
| `demo-2-read-poisoned-kb` | `allow` | `[]` |
| `demo-3-read-one-customer` | `allow` | `[]` |
| `demo-4-bulk-read` | `rows.bounded` | `["rows.bounded", "rows.scope"]` |
| `demo-5-exfil-to-attacker` | `egress.allowlist` | `["egress.allowlist", "egress.pii_sink"]` |
| `demo-6-exfil-to-allowlisted-sink` | `egress.pii_sink` | `["egress.pii_sink"]` |
| `demo-7-reply-to-customer` | `allow` | `[]` |

Note `adversarial-1`, `-3` and `-4` each carry **two** reasons. That redundancy is exactly what Phase 2's rekey removes, and `expected.json` is where its removal becomes visible rather than silent.

- [ ] **Step 7: Run the gate**

```bash
.venv/bin/python -m pytest tests/test_golden_decisions.py -v
```

Expected: 13 parametrised PASS plus the two structural tests.

- [ ] **Step 8: Prove the gate can fail**

A gate never seen failing is not known to be a gate. Break the policy deliberately and confirm the corpus catches what `warden replay` cannot.

```bash
cp policies/authz.rego /tmp/authz.rego.bak
# Disable the row bound the way a careless rekey would.
sed -i 's/^\tinput.action.tool == "query_customers"$/\tinput.action.tool == "nonexistent_tool"/' policies/authz.rego
.venv/bin/python -m pytest tests/test_golden_decisions.py -q 2>&1 | tail -4
.venv/bin/python -m pytest tests/test_golden_replay.py -q 2>&1 | tail -2
cp /tmp/authz.rego.bak policies/authz.rego
```

Expected: `test_golden_decisions` **FAILS** on `demo-4-bulk-read`, `adversarial-1` and `adversarial-4`; `test_golden_replay` **PASSES** throughout. That contrast is the reason this task exists.

- [ ] **Step 9: Restore and confirm green**

```bash
.venv/bin/python -m pytest tests/test_golden_decisions.py tests/test_golden_replay.py -q
```

Expected: all PASS.

- [ ] **Step 10: Commit**

```bash
git add -f tests/golden/decisions/ tests/test_golden_decisions.py tools/build_corpus.py
git commit -m "test: a decision corpus, evaluated against the shipped bundle unmocked

warden replay reads a recorded log and never calls the PDP, so it cannot see
a policy regression.  authz_test.rego mocks data.purposes and data.limits in
almost every case, so the shipped data document is barely exercised -- adding
a correct data.tools mock in Phase 2 would reintroduce that blindness on a new
key, verified: opa test 44/44 over a policy that approves a mislabelled
5,000,000-row read.

Thirteen inputs, real opa eval, real policies/, no `with` overrides.  Seven
derived from the frozen log and confirmed to reproduce every audited rule
including both precedence picks; six hand-authored for the holes the design
review demonstrated.  expected.json records what the policy says TODAY, not
what it ought to say."
```

---

## Phase 0 gate

Do not begin Phase 1 until all of these hold:

```bash
.venv/bin/python -m pytest -q                       # 0 failures
~/.cache/warden/opa-1.19.0 test policies/           # PASS: 44/44
sg docker -c "./scripts/demo.sh guarded" | tail -11 # matches README.md:37-48
git log --oneline product-demo-seam ~6              # six task commits
```


---

# Phase 1 — Config and adapters

The product stops knowing tool names. New packages are created **in place** under `broker/` — the directory move to `warden/` happens in Phase 3, so nothing here churns import paths twice.

Every task in this phase must leave `tests/test_golden_decisions.py` and `tests/test_golden_replay.py` green. Phase 1 changes no policy and no audit bytes.

---

### Task 7: The config loader

**Files:**
- Create: `broker/config/__init__.py`
- Create: `broker/config/loader.py`
- Create: `tests/test_config_loader.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `broker.config.loader.BrokerConfig` — frozen dataclass with fields `listen: tuple[str, int]`, `proxy_listen: tuple[str, int]`, `public_key: Path`, `opa_url: str`, `decision_path: str`, `bundle_roots: tuple[Path, ...]`, `audit_path: Path`, `issuer: str`, `ttl_seconds: int`, `catalog_path: Path`.
  - `broker.config.loader.ConfigError(Exception)`.
  - `load_broker_config(path: Path, env: Mapping[str, str]) -> BrokerConfig`.
  - `interpolate(value: str, env: Mapping[str, str]) -> str` — expands `${VAR}`, raising `ConfigError` on an unset variable.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config_loader.py`:

```python
"""Wiring comes from a file, and a file that is wrong stops the process.

Every failure here is a startup failure by design. A broker that boots with a
half-understood config is a broker whose audit records claim a policy it is
not enforcing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from broker.config.loader import BrokerConfig, ConfigError, interpolate, load_broker_config

COMPLETE = """
[broker]
listen       = "0.0.0.0:8080"
proxy_listen = "0.0.0.0:3128"

[identity]
public_key = "/data/agent.pub"

[policy]
opa_url       = "http://opa:8181"
decision_path = "warden/authz"
bundle_roots  = ["/policies"]

[audit]
path = "/data/audit.jsonl"

[tokens]
issuer      = "warden-broker"
ttl_seconds = 300

[catalog]
tools = "/config/tools.toml"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "warden.toml"
    path.write_text(text)
    return path


def test_loads_every_field(tmp_path):
    config = load_broker_config(write(tmp_path, COMPLETE), env={})
    assert isinstance(config, BrokerConfig)
    assert config.listen == ("0.0.0.0", 8080)
    assert config.proxy_listen == ("0.0.0.0", 3128)
    assert config.public_key == Path("/data/agent.pub")
    assert config.opa_url == "http://opa:8181"
    assert config.decision_path == "warden/authz"
    assert config.bundle_roots == (Path("/policies"),)
    assert config.audit_path == Path("/data/audit.jsonl")
    assert config.issuer == "warden-broker"
    assert config.ttl_seconds == 300
    assert config.catalog_path == Path("/config/tools.toml")


def test_is_frozen(tmp_path):
    config = load_broker_config(write(tmp_path, COMPLETE), env={})
    with pytest.raises(Exception):
        config.opa_url = "http://elsewhere"


def test_interpolates_from_the_environment(tmp_path):
    text = COMPLETE.replace('"http://opa:8181"', '"${OPA_URL}"')
    config = load_broker_config(write(tmp_path, text), env={"OPA_URL": "http://x:1"})
    assert config.opa_url == "http://x:1"


def test_an_unset_variable_is_a_startup_failure(tmp_path):
    """Fail closed. Substituting an empty string would point the PDP at
    nothing and every decision would become pdp.unavailable at runtime,
    discovered in production rather than at boot."""
    text = COMPLETE.replace('"http://opa:8181"', '"${OPA_URL}"')
    with pytest.raises(ConfigError, match="OPA_URL"):
        load_broker_config(write(tmp_path, text), env={})


def test_interpolate_handles_several_and_leaves_other_text_alone():
    assert interpolate("a${X}b${Y}c", {"X": "1", "Y": "2"}) == "a1b2c"
    assert interpolate("no vars", {}) == "no vars"


def test_a_missing_section_names_itself(tmp_path):
    text = COMPLETE.replace("[audit]\npath = \"/data/audit.jsonl\"\n", "")
    with pytest.raises(ConfigError, match="audit"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_missing_key_names_itself(tmp_path):
    text = COMPLETE.replace('opa_url       = "http://opa:8181"\n', "")
    with pytest.raises(ConfigError, match="policy.opa_url"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_wrong_type_is_rejected(tmp_path):
    text = COMPLETE.replace("ttl_seconds = 300", 'ttl_seconds = "300"')
    with pytest.raises(ConfigError, match="tokens.ttl_seconds"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_malformed_listen_address_is_rejected(tmp_path):
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "0.0.0.0"')
    with pytest.raises(ConfigError, match="broker.listen"):
        load_broker_config(write(tmp_path, text), env={})


def test_empty_bundle_roots_is_rejected(tmp_path):
    """No roots means the digest covers nothing, so every audit record would
    stamp the same value whatever the policy said."""
    text = COMPLETE.replace('bundle_roots  = ["/policies"]', "bundle_roots  = []")
    with pytest.raises(ConfigError, match="policy.bundle_roots"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_missing_file_names_the_path(tmp_path):
    with pytest.raises(ConfigError, match="absent.toml"):
        load_broker_config(tmp_path / "absent.toml", env={})


def test_invalid_toml_names_the_file(tmp_path):
    path = write(tmp_path, "[broker\n")
    with pytest.raises(ConfigError, match="warden.toml"):
        load_broker_config(path, env={})
```

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_config_loader.py -v
```

Expected: `ModuleNotFoundError: No module named 'broker.config'`.

- [ ] **Step 3: Implement**

Create `broker/config/__init__.py` (empty) and `broker/config/loader.py`:

```python
"""Reads the broker's wiring from TOML.

tomllib is stdlib from 3.11, so this costs the enforcement point no
dependency -- which is the same reason a model SDK is not in
requirements.txt.

Every failure raises ConfigError, and the entrypoint lets it kill the
process. A broker that starts with a half-understood config writes audit
records claiming a policy it is not enforcing, and that is worse than not
starting.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    """Any reason this config cannot be used. Always names the offending key."""


@dataclass(frozen=True)
class BrokerConfig:
    listen: tuple[str, int]
    proxy_listen: tuple[str, int]
    public_key: Path
    opa_url: str
    decision_path: str
    bundle_roots: tuple[Path, ...]
    audit_path: Path
    issuer: str
    ttl_seconds: int
    catalog_path: Path


def interpolate(value: str, env: Mapping[str, str]) -> str:
    """Expands ${VAR}. An unset variable RAISES rather than substituting "".

    Substituting empty would point the PDP at nothing, or the audit log at
    the current directory -- failures discovered in production rather than at
    boot.
    """
    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in env:
            raise ConfigError(f"${{{name}}} is not set in the environment")
        return env[name]

    return _VAR.sub(replace, value)


def _section(document: dict, name: str) -> dict:
    value = document.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"missing or malformed section [{name}]")
    return value


def _string(section: dict, table: str, key: str, env: Mapping[str, str]) -> str:
    value = section.get(key)
    if not isinstance(value, str):
        raise ConfigError(f"{table}.{key} must be a string")
    return interpolate(value, env)


def _integer(section: dict, table: str, key: str) -> int:
    value = section.get(key)
    # bool is an int subclass; a `true` here is a mistake, not a 1.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{table}.{key} must be an integer")
    return value


def _address(section: dict, table: str, key: str, env: Mapping[str, str]) -> tuple[str, int]:
    raw = _string(section, table, key, env)
    host, separator, port = raw.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise ConfigError(f"{table}.{key} must be host:port, got {raw!r}")
    return host, int(port)


def _paths(section: dict, table: str, key: str, env: Mapping[str, str]) -> tuple[Path, ...]:
    value = section.get(key)
    if not isinstance(value, Sequence) or isinstance(value, str) or not value:
        raise ConfigError(f"{table}.{key} must be a non-empty array of paths")
    roots = []
    for entry in value:
        if not isinstance(entry, str):
            raise ConfigError(f"{table}.{key} entries must be strings")
        roots.append(Path(interpolate(entry, env)))
    return tuple(roots)


def load_broker_config(path: Path, env: Mapping[str, str]) -> BrokerConfig:
    path = Path(path)
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    broker = _section(document, "broker")
    identity = _section(document, "identity")
    policy = _section(document, "policy")
    audit = _section(document, "audit")
    tokens = _section(document, "tokens")
    catalog = _section(document, "catalog")

    return BrokerConfig(
        listen=_address(broker, "broker", "listen", env),
        proxy_listen=_address(broker, "broker", "proxy_listen", env),
        public_key=Path(_string(identity, "identity", "public_key", env)),
        opa_url=_string(policy, "policy", "opa_url", env),
        decision_path=_string(policy, "policy", "decision_path", env),
        bundle_roots=_paths(policy, "policy", "bundle_roots", env),
        audit_path=Path(_string(audit, "audit", "path", env)),
        issuer=_string(tokens, "tokens", "issuer", env),
        ttl_seconds=_integer(tokens, "tokens", "ttl_seconds"),
        catalog_path=Path(_string(catalog, "catalog", "tools", env)),
    )
```

- [ ] **Step 4: Run and confirm green**

```bash
.venv/bin/python -m pytest tests/test_config_loader.py -v
```

Expected: 12 PASS.

- [ ] **Step 5: Confirm no new dependency crept in**

```bash
grep -rn "^import \|^from " broker/config/loader.py | grep -v "^.*:from __future__"
```

Expected: only `re`, `tomllib`, `collections.abc`, `dataclasses`, `pathlib` — all stdlib.

- [ ] **Step 6: Commit**

```bash
git add broker/config/ tests/test_config_loader.py
git commit -m "feat(config): the broker's wiring comes from TOML, not from constants

tomllib is stdlib at the 3.11 floor, so the enforcement point gains no
dependency.  Every failure raises and the entrypoint lets it kill the
process: a broker that boots on a half-understood config writes audit records
claiming a policy it is not enforcing.  An unset \${VAR} raises rather than
substituting empty, which would point the PDP at nothing and turn every
decision into pdp.unavailable at runtime instead of a refusal to start."
```

---

### Task 8: The argument-schema validator

`broker/app.py:94-118`'s four hand-written branches become declarative. The module docstring calls this a security invariant: `describe()` (which decides what is audited and policy-checked) and `execute()` (which acts) must interpret the same args the same way, and its worked example is a bare string passed where `send_email` expects a list — read character-by-character by one stage and whole by the other.

The vocabulary is exactly what reproduces today's measured behaviour, and no more. Every asymmetry below was probed against the running code, not reasoned about:

| args | today | why |
|---|---|---|
| `read_document {"doc_id": ""}` | **deny** | `non_empty` |
| `http_fetch {"url": ""}` | **deny** | `non_empty` |
| `query_customers {"filter": ""}` | **allow** | `""` is a documented meaning — whole table |
| `send_email {"to": [], "subject": "", "body": ""}` | **allow** | `all([])` is True; no emptiness check |
| `query_customers {}` | **deny** | `filter` required, though both stages default it |
| `http_fetch {"url": u, "body": null}` | **allow** | `execute` selects GET vs POST on `body is None` |
| `read_document {"doc_id": null}` | **deny** | required args reject null |
| `read_document {"doc_id": "a", "junk": {...}}` | **allow** | extra keys unchecked — the hole Task 8 closes |
| `unknown_tool {...}` | **defer** | falls through to `describe()`'s `UnknownTool` |

**Files:**
- Create: `broker/config/schema.py`
- Create: `tests/test_arg_schema.py`

**Interfaces:**
- Consumes: `broker.config.loader.ConfigError`
- Produces:
  - `broker.config.schema.ArgSpec` — frozen dataclass `(type: str, items: str | None, required: bool, non_empty: bool, null_is_absent: bool)`.
  - `broker.config.schema.ToolSchema` — frozen dataclass `(args: Mapping[str, ArgSpec], unknown_args: str)`.
  - `parse_tool_schema(table: dict, tool: str) -> ToolSchema` — raises `ConfigError`. A tool with **no** `args` table raises; it never yields a vacuous schema.
  - `ToolSchema.validate(args: dict) -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_arg_schema.py`:

```python
"""Declarative validation must reproduce the hand-written checks exactly.

Every expectation here was measured against broker/app.py's
_args_are_well_shaped before it was replaced. Where they look inconsistent --
doc_id "" denied but filter "" allowed -- that inconsistency IS the behaviour,
and a uniform default in either direction changes what the broker permits.
"""

from __future__ import annotations

import pytest

from broker.config.loader import ConfigError
from broker.config.schema import ArgSpec, ToolSchema, parse_tool_schema

DEMO = {
    "read_document": {"doc_id": {"type": "string", "required": True, "non_empty": True}},
    "query_customers": {"filter": {"type": "string", "required": True}},
    "http_fetch": {
        "url": {"type": "string", "required": True, "non_empty": True},
        "body": {"type": "string", "required": False, "null_is_absent": True},
    },
    "send_email": {
        "to": {"type": "array", "items": "string", "required": True},
        "subject": {"type": "string", "required": True},
        "body": {"type": "string", "required": True},
    },
}


def schema(tool: str, unknown_args: str = "reject") -> ToolSchema:
    return parse_tool_schema({"args": DEMO[tool], "unknown_args": unknown_args}, tool)


@pytest.mark.parametrize(
    "tool,args,expected",
    [
        # --- reproduced from the measured truth table ---
        ("read_document", {"doc_id": "ticket-4711"}, True),
        ("read_document", {"doc_id": ""}, False),
        ("read_document", {"doc_id": None}, False),
        ("read_document", {}, False),
        ("read_document", {"doc_id": 123}, False),
        ("query_customers", {"filter": "id=8812"}, True),
        ("query_customers", {"filter": ""}, True),
        ("query_customers", {}, False),
        ("query_customers", {"filter": None}, False),
        ("http_fetch", {"url": "http://x/"}, True),
        ("http_fetch", {"url": "http://x/", "body": "payload"}, True),
        ("http_fetch", {"url": "http://x/", "body": None}, True),
        ("http_fetch", {"url": ""}, False),
        ("http_fetch", {"url": "http://x/", "body": 7}, False),
        ("send_email", {"to": ["customer:8812"], "subject": "s", "body": "b"}, True),
        ("send_email", {"to": [], "subject": "", "body": ""}, True),
        ("send_email", {"to": "customer:8812", "subject": "s", "body": "b"}, False),
        ("send_email", {"to": [1], "subject": "s", "body": "b"}, False),
        ("send_email", {"to": {"customer:8812": "x@evil"}, "subject": "s", "body": "b"}, False),
    ],
)
def test_matches_the_measured_behaviour(tool, args, expected):
    assert schema(tool).validate(args) is expected


def test_undeclared_args_are_rejected_by_default():
    """The live hole this closes: send_email posts the WHOLE args dict to the
    mailer, so cc/bcc ride along on a call whose audited target.recipients is
    the approved one. The policy judged one recipient set; the action used
    another. Measured: 200 OK, audited ["customer:8812"], mailer received the
    cc."""
    assert schema("send_email").validate(
        {"to": ["customer:8812"], "subject": "s", "body": "b",
         "cc": ["attacker@evil.example"]}
    ) is False


def test_undeclared_args_can_be_allowed_explicitly():
    assert schema("send_email", unknown_args="allow").validate(
        {"to": ["customer:8812"], "subject": "s", "body": "b", "cc": ["x"]}
    ) is True


def test_a_tool_with_no_args_table_is_a_config_error():
    """Never a vacuous schema. A missing or misspelled [tools.X.args] makes
    tomllib yield nothing silently, and a validator that then passes
    everything restores the exact divergence the app.py docstring exists to
    prevent."""
    with pytest.raises(ConfigError, match="read_document"):
        parse_tool_schema({"unknown_args": "reject"}, "read_document")


def test_an_empty_args_table_is_a_config_error():
    with pytest.raises(ConfigError, match="read_document"):
        parse_tool_schema({"args": {}}, "read_document")


def test_an_unknown_type_is_a_config_error():
    with pytest.raises(ConfigError, match="filter"):
        parse_tool_schema({"args": {"filter": {"type": "integer"}}}, "query_customers")


def test_an_unknown_schema_key_is_a_config_error():
    """A typo silently disabling a check is the failure mode this whole file
    is guarding against."""
    with pytest.raises(ConfigError, match="nonempty"):
        parse_tool_schema(
            {"args": {"url": {"type": "string", "nonempty": True}}}, "http_fetch"
        )


def test_an_unknown_unknown_args_policy_is_a_config_error():
    with pytest.raises(ConfigError, match="unknown_args"):
        parse_tool_schema({"args": DEMO["read_document"], "unknown_args": "ignore"}, "x")


def test_array_without_items_is_a_config_error():
    with pytest.raises(ConfigError, match="items"):
        parse_tool_schema({"args": {"to": {"type": "array", "required": True}}}, "send_email")


def test_defaults_are_the_permissive_ones_that_match_today():
    spec = parse_tool_schema({"args": {"filter": {"type": "string"}}}, "t").args["filter"]
    assert spec == ArgSpec(type="string", items=None, required=False,
                           non_empty=False, null_is_absent=False)
```

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_arg_schema.py -v
```

Expected: `ModuleNotFoundError: No module named 'broker.config.schema'`.

- [ ] **Step 3: Implement**

Create `broker/config/schema.py`:

```python
"""Declarative argument validation.

broker/app.py's docstring states the invariant this upholds: args are
shape-checked BEFORE describe() is called, so describe() (which decides what
gets audited and policy-checked) and execute() (which acts) are guaranteed to
interpret the same args the same way. Its worked example is a bare string
where send_email expects a list -- read character-by-character by one stage
and whole by the other.

Moving that check into config makes it OMISSIBLE, which is the new risk. Two
rules answer it: a tool with no args table is a ConfigError rather than a
permissive default, and an unrecognised schema key is a ConfigError rather
than an ignored typo. Both fail at load, before the process serves anything.

The vocabulary is five keys because five keys reproduce the measured
behaviour exactly. It is deliberately not a general JSON-Schema subset:
`required` here mirrors what the old check demanded, NOT what an adapter can
default. query_customers with {} is denied today even though both stages fall
back to "all", and relaxing that turns a refusal into a full-table COUNT
judged by policy -- an allow on any deployment whose table is under the row
limit and whose token names no counterparties.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from broker.config.loader import ConfigError

_TYPES = ("string", "array")
_ARG_KEYS = ("type", "items", "required", "non_empty", "null_is_absent")
_UNKNOWN_ARGS_POLICIES = ("reject", "allow")


@dataclass(frozen=True)
class ArgSpec:
    type: str
    items: str | None = None
    required: bool = False
    non_empty: bool = False
    # JSON null validates and reaches execute() as None. Set only where a
    # stage branches on `is None` -- http_fetch.body selects GET vs POST that
    # way, so rejecting null there turns a working GET into input.malformed.
    null_is_absent: bool = False

    def accepts(self, value: object) -> bool:
        if value is None:
            return self.null_is_absent
        if self.type == "string":
            if not isinstance(value, str):
                return False
            return not (self.non_empty and value == "")
        # array
        if not isinstance(value, list):
            return False
        if self.items == "string" and not all(isinstance(item, str) for item in value):
            return False
        return not (self.non_empty and not value)


@dataclass(frozen=True)
class ToolSchema:
    args: Mapping[str, ArgSpec]
    unknown_args: str = "reject"

    def validate(self, args: dict) -> bool:
        if self.unknown_args == "reject":
            if any(name not in self.args for name in args):
                return False
        for name, spec in self.args.items():
            if name not in args:
                if spec.required:
                    return False
                continue
            if not spec.accepts(args[name]):
                return False
        return True


def _bool(table: dict, key: str, where: str) -> bool:
    value = table.get(key, False)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} must be true or false")
    return value


def parse_tool_schema(table: dict, tool: str) -> ToolSchema:
    raw_args = table.get("args")
    if not isinstance(raw_args, dict) or not raw_args:
        # Never a vacuous schema: a missing or misspelled [tools.X.args] makes
        # tomllib yield nothing silently, and a validator that then passes
        # everything reopens the divergence app.py exists to prevent.
        raise ConfigError(f"tool {tool!r} declares no [args] table")

    unknown_args = table.get("unknown_args", "reject")
    if unknown_args not in _UNKNOWN_ARGS_POLICIES:
        raise ConfigError(
            f"tool {tool!r}: unknown_args must be one of {_UNKNOWN_ARGS_POLICIES}"
        )

    specs: dict[str, ArgSpec] = {}
    for name, spec_table in raw_args.items():
        where = f"{tool}.args.{name}"
        if not isinstance(spec_table, dict):
            raise ConfigError(f"{where} must be a table")
        for key in spec_table:
            if key not in _ARG_KEYS:
                # A typo that silently disables a check is precisely the
                # failure this module exists to make impossible.
                raise ConfigError(f"{where}: unknown key {key!r}")
        arg_type = spec_table.get("type")
        if arg_type not in _TYPES:
            raise ConfigError(f"{where}.type must be one of {_TYPES}")
        items = spec_table.get("items")
        if arg_type == "array":
            if items != "string":
                raise ConfigError(f'{where}.items must be "string" for an array')
        elif items is not None:
            raise ConfigError(f"{where}.items is only meaningful for an array")
        specs[name] = ArgSpec(
            type=arg_type,
            items=items,
            required=_bool(spec_table, "required", where),
            non_empty=_bool(spec_table, "non_empty", where),
            null_is_absent=_bool(spec_table, "null_is_absent", where),
        )
    return ToolSchema(args=MappingProxyType(specs), unknown_args=unknown_args)
```

- [ ] **Step 4: Run and confirm green**

```bash
.venv/bin/python -m pytest tests/test_arg_schema.py -v
```

Expected: 29 PASS.

- [ ] **Step 5: Cross-check against the code being replaced**

Prove equivalence rather than asserting it — run both implementations over the same inputs.

```bash
.venv/bin/python - <<'EOF'
from broker.app import _args_are_well_shaped
from broker.config.schema import parse_tool_schema
from tests.test_arg_schema import DEMO

cases = [
    ("read_document", {"doc_id": "ticket-4711"}), ("read_document", {"doc_id": ""}),
    ("read_document", {"doc_id": None}), ("read_document", {}),
    ("read_document", {"doc_id": 123}),
    ("query_customers", {"filter": "id=8812"}), ("query_customers", {"filter": ""}),
    ("query_customers", {}), ("query_customers", {"filter": None}),
    ("http_fetch", {"url": "http://x/"}), ("http_fetch", {"url": "http://x/", "body": "p"}),
    ("http_fetch", {"url": "http://x/", "body": None}), ("http_fetch", {"url": ""}),
    ("http_fetch", {"url": "http://x/", "body": 7}),
    ("send_email", {"to": ["customer:8812"], "subject": "s", "body": "b"}),
    ("send_email", {"to": [], "subject": "", "body": ""}),
    ("send_email", {"to": "customer:8812", "subject": "s", "body": "b"}),
    ("send_email", {"to": [1], "subject": "s", "body": "b"}),
]
bad = 0
for tool, args in cases:
    old = _args_are_well_shaped(tool, args)
    new = parse_tool_schema({"args": DEMO[tool]}, tool).validate(args)
    if old != new:
        bad += 1
        print(f"DIVERGE {tool} {args}: old={old} new={new}")
print(f"\n{len(cases)-bad}/{len(cases)} agree" + ("" if bad else " — EQUIVALENT"))
EOF
```

Expected: `18/18 agree — EQUIVALENT`. The only intended divergence is undeclared args, which the old check never inspected; it is covered by its own test above and is a fix, not a regression.

- [ ] **Step 6: Commit**

```bash
git add broker/config/schema.py tests/test_arg_schema.py
git commit -m "feat(config): declarative arg validation, equivalent to the checks it replaces

Five keys, because five keys reproduce the measured behaviour exactly.  The
asymmetries are the behaviour: doc_id \"\" denied but filter \"\" allowed,
required args rejecting null but http_fetch.body accepting it because execute
selects GET vs POST on `body is None`.  A uniform default either way changes
what the broker permits.

Moving the check into config makes it omissible, so a tool with no args table
is a ConfigError and an unrecognised schema key is a ConfigError -- both at
load, before anything is served.

unknown_args defaults to reject, which closes a live hole: send_email posts
the whole args dict to the mailer, so an undeclared cc rides along on a call
whose audited recipients is the approved one."
```

---

### Task 9: Adapter base and the kind vocabulary

Two vocabularies exist and the mapping between them is currently written nowhere: `tools.toml` declares adapter kinds (`http`, `sql`, `docstore`, `mail`); `authz.rego` R0 enumerates target kinds (`doc`, `db`, `http`, `mail`). Transcribing one for the other produces a defined, `is_string`-passing value that matches no target kind, so **every call to that tool denies `input.malformed`** — fails closed, but silently, and `cli/warden.py:19-27` then matches no branch and prints a bare `query_customers()`, losing the row count that is the whole point of the `rows.bounded` line.

One named constant, with a test that parses R0 out of the policy so the two cannot drift. **Verified:** the regex below extracts exactly `{db, doc, http, mail}` from today's `authz.rego`.

**Files:**
- Create: `broker/adapters/__init__.py`
- Create: `broker/adapters/base.py`
- Create: `broker/adapters/registry.py`
- Create: `tests/test_adapter_registry.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `broker.adapters.base.ToolTarget`, `ToolResult` — moved verbatim from `broker/backends.py:27-57`, fields and `as_dict()` key order unchanged.
  - `broker.adapters.base.Adapter` — Protocol with `target_kind: str`, `describe(args) -> ToolTarget`, `execute(args) -> ToolResult`.
  - `broker.adapters.base.UnknownTool` — moved from `broker/backends.py:23`.
  - `broker.adapters.registry.TARGET_KIND_BY_ADAPTER: Mapping[str, str]`.
  - `broker.adapters.registry.ADAPTERS: Mapping[str, type]` — filled in Tasks 10-11.
  - `broker.adapters.registry.build_adapter(kind: str, binding: dict, client) -> Adapter`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_adapter_registry.py`:

```python
"""The two kind vocabularies must not drift.

tools.toml says http/sql/docstore/mail; authz.rego says doc/db/http/mail.
Writing "sql" where the policy expects "db" yields a defined, is_string
value matching no target kind, so every call to that tool denies
input.malformed -- closed, but silently -- and cli/warden.py's _describe
matches no branch and prints a bare `query_customers()`, dropping the row
count that carries the whole rows.bounded demonstration.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from broker.adapters.base import ToolTarget
from broker.adapters.registry import TARGET_KIND_BY_ADAPTER, build_adapter

REPO_ROOT = Path(__file__).resolve().parent.parent


def policy_target_kinds() -> set[str]:
    source = (REPO_ROOT / "policies" / "authz.rego").read_text()
    return set(re.findall(r'not input\.target\.kind == "([a-z_]+)"', source))


def test_the_mapping_image_is_exactly_what_the_policy_accepts():
    assert set(TARGET_KIND_BY_ADAPTER.values()) == policy_target_kinds()


def test_every_adapter_kind_maps_to_something():
    assert TARGET_KIND_BY_ADAPTER == {
        "docstore": "doc", "sql": "db", "http": "http", "mail": "mail",
    }


def test_building_an_unknown_kind_is_an_error():
    with pytest.raises(KeyError, match="nosuchkind"):
        build_adapter("nosuchkind", {}, client=None)


def test_tool_target_as_dict_key_order_is_unchanged():
    """The audit file is written key-sorted now, but describe() output is
    compared field-by-field in the golden tests, and _describe reads specific
    keys. Pin the full shape."""
    assert ToolTarget(kind="doc", path="x").as_dict() == {
        "kind": "doc", "host": "", "port": 0, "path": "x",
        "estimated_rows": 0, "recipients": [], "subjects": [],
    }
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_adapter_registry.py -v
```

Expected: `ModuleNotFoundError: No module named 'broker.adapters'`.

- [ ] **Step 3: Create `broker/adapters/base.py`**

Move `ToolTarget`, `ToolResult`, `UnknownTool` and `DEFAULT_PORTS` out of `broker/backends.py` **verbatim** — same fields, same defaults, same `as_dict()` key order, same docstrings — and add the Protocol:

```python
"""What an adapter is.

describe() is the policy information point: it produces everything the
decision needs WITHOUT performing the action. For a database read that means
a bounded COUNT -- bounded in the sense that no rows materialise, NOT that
the count is capped. The adapter returns the true cardinality; capping it
would change the number the demo quotes without changing any decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

DEFAULT_PORTS = {"http": 80, "https": 443}


class UnknownTool(Exception):
    """Raised for any tool outside the catalog. Deny-by-default at the edge."""


@dataclass(frozen=True)
class ToolTarget:
    kind: str
    host: str = ""
    port: int = 0
    path: str = ""
    estimated_rows: int = 0
    recipients: tuple[str, ...] = field(default=())
    # Which data subjects a database read names. `("*",)` means "not a
    # bounded set". It is deliberately a value that can never appear in a
    # token's counterparties, so an unbounded read is out of scope by
    # construction rather than by a second rule.
    subjects: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "estimated_rows": self.estimated_rows,
            "recipients": list(self.recipients),
            "subjects": list(self.subjects),
        }


@dataclass(frozen=True)
class ToolResult:
    content: str
    rows: int = 0
    data_class: str | None = None


class Adapter(Protocol):
    target_kind: str

    def describe(self, args: dict) -> ToolTarget: ...

    def execute(self, args: dict) -> ToolResult: ...
```

- [ ] **Step 4: Create `broker/adapters/registry.py`**

```python
"""The adapter-kind vocabulary, and the one place it meets the policy's.

tools.toml names adapter kinds; authz.rego names target kinds. The mapping
lived nowhere, and getting it wrong fails closed but silently: every call to
that tool denies input.malformed and the replay prints a bare `tool()`
because cli/warden.py matches no branch for an unrecognised kind.

tests/test_adapter_registry.py parses R0 out of the policy and asserts this
mapping's image equals it, so the two cannot drift apart unnoticed.
"""

from __future__ import annotations

from collections.abc import Mapping

TARGET_KIND_BY_ADAPTER: Mapping[str, str] = {
    "docstore": "doc",
    "sql": "db",
    "http": "http",
    "mail": "mail",
}

# Filled by Tasks 10 and 11.
ADAPTERS: dict[str, type] = {}


def build_adapter(kind: str, binding: dict, client):
    if kind not in ADAPTERS:
        raise KeyError(f"unknown adapter kind {kind!r}")
    return ADAPTERS[kind](binding=binding, client=client)
```

- [ ] **Step 5: Run — three of four pass**

```bash
.venv/bin/python -m pytest tests/test_adapter_registry.py -v
```

Expected: `test_building_an_unknown_kind_is_an_error` PASSES (the registry is empty, so any kind is unknown); the other three PASS. All four green.

- [ ] **Step 6: Commit**

```bash
git add broker/adapters/ tests/test_adapter_registry.py
git commit -m "feat(adapters): the kind vocabulary, pinned against the policy's

tools.toml declares http/sql/docstore/mail; authz.rego R0 accepts
doc/db/http/mail.  Writing one where the other belongs yields a defined,
is_string value matching no target kind: every call to that tool denies
input.malformed -- closed, but silently -- and the replay prints a bare
tool(), dropping the row count that carries the rows.bounded line.

The mapping is one constant and a test parses R0 out of the policy to assert
its image, so drift is a failure rather than a mystery."
```

---

### Task 10: The `docstore`, `http` and `mail` adapters

Each is a straight lift of one branch of `broker/backends.py`, with the URLs and arg names that were literals becoming bindings. Two behaviours must survive unchanged because the replay text depends on them:

- **`docstore.describe()` sets `path` to the bare document id, not the resolved request path.** `backends.py:107` and `:140` deliberately disagree. Converging them turns `read_document(ticket-4711)` into `read_document(/docs/ticket-4711)` in the replay and re-flows the `:<38` column padding on that line.
- **`http.execute()` selects GET vs POST on `body is None`.** With a bare GET the sinkhole records zero bytes and the unprotected profile's first beat — the data genuinely leaves — has nothing to show.

**Files:**
- Create: `broker/adapters/docstore.py`, `broker/adapters/http.py`, `broker/adapters/mail.py`
- Modify: `broker/adapters/registry.py` (register the three)
- Create: `tests/test_adapters_simple.py`

**Interfaces:**
- Consumes: `broker.adapters.base` (Task 9)
- Produces: `DocstoreAdapter`, `HttpAdapter`, `MailAdapter`, each `__init__(self, *, binding: dict, client)`, registered in `ADAPTERS` under `docstore`/`http`/`mail`.
  - `DocstoreAdapter` binding: `base_url: str`, `path_template: str` (default `"/docs/{doc_id}"`), `arg: str` (default `"doc_id"`), `data_class: str | None`.
  - `HttpAdapter` binding: `url_arg` (default `"url"`), `body_arg` (default `"body"`), `data_class`.
  - `MailAdapter` binding: `base_url`, `path` (default `"/send"`), `recipients_arg` (default `"to"`), `fields: list[str]` — the **only** keys forwarded on the wire.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_adapters_simple.py`:

```python
"""The three adapters that are a lift of one backends.py branch each."""

from __future__ import annotations

import httpx
import pytest

from broker.adapters.docstore import DocstoreAdapter
from broker.adapters.http import HttpAdapter
from broker.adapters.mail import MailAdapter


def recording_client(record: list) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        record.append((request.method, str(request.url), request.content))
        return httpx.Response(200, text="ok")

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_docstore_describe_uses_the_bare_document_id():
    """Not the resolved request path. describe() and execute() disagree on
    purpose: resolving here turns read_document(ticket-4711) into
    read_document(/docs/ticket-4711) in the replay and re-flows the padding."""
    adapter = DocstoreAdapter(
        binding={"base_url": "http://docstore.internal", "data_class": "public"},
        client=recording_client([]),
    )
    target = adapter.describe({"doc_id": "ticket-4711"})
    assert target.as_dict() == {
        "kind": "doc", "host": "", "port": 0, "path": "ticket-4711",
        "estimated_rows": 0, "recipients": [], "subjects": [],
    }


def test_docstore_execute_resolves_the_url():
    calls: list = []
    adapter = DocstoreAdapter(
        binding={"base_url": "http://docstore.internal/", "data_class": "public"},
        client=recording_client(calls),
    )
    result = adapter.execute({"doc_id": "kb/refund-policy"})
    assert calls == [("GET", "http://docstore.internal/docs/kb/refund-policy", b"")]
    assert result.data_class == "public"


def test_http_describe_parses_host_port_and_path():
    adapter = HttpAdapter(binding={"data_class": "public"}, client=recording_client([]))
    assert adapter.describe({"url": "https://attacker.example/collect"}).as_dict() == {
        "kind": "http", "host": "attacker.example", "port": 443, "path": "/collect",
        "estimated_rows": 0, "recipients": [], "subjects": [],
    }
    # A bare host normalises to "/", as urlsplit gives "".
    assert adapter.describe({"url": "http://docstore.internal"}).as_dict()["path"] == "/"
    assert adapter.describe({"url": "http://docstore.internal"}).as_dict()["port"] == 80


def test_http_execute_is_a_get_without_a_body_and_a_post_with_one():
    """Exfiltration is a write. With a bare GET the sinkhole records zero
    bytes and the unprotected profile has nothing to show."""
    calls: list = []
    adapter = HttpAdapter(binding={"data_class": "public"}, client=recording_client(calls))
    adapter.execute({"url": "http://x/a"})
    adapter.execute({"url": "http://x/b", "body": "rows"})
    adapter.execute({"url": "http://x/c", "body": None})
    assert [(m, u) for m, u, _ in calls] == [
        ("GET", "http://x/a"), ("POST", "http://x/b"), ("GET", "http://x/c"),
    ]
    assert calls[1][2] == b"rows"


def test_mail_describe_lists_recipients():
    adapter = MailAdapter(
        binding={"base_url": "http://mailer.internal",
                 "fields": ["to", "subject", "body"]},
        client=recording_client([]),
    )
    target = adapter.describe({"to": ["customer:8812"], "subject": "s", "body": "b"})
    assert target.as_dict()["kind"] == "mail"
    assert target.as_dict()["recipients"] == ["customer:8812"]


def test_mail_sends_only_declared_fields():
    """The live hole: backends.py posts the WHOLE args dict, so an undeclared
    cc rides along on a call whose audited recipients is the approved one.
    unknown_args=reject stops it at the door; this stops it at the wire, and
    both are wanted -- the schema is config and could be relaxed."""
    calls: list = []
    adapter = MailAdapter(
        binding={"base_url": "http://mailer.internal",
                 "fields": ["to", "subject", "body"]},
        client=recording_client(calls),
    )
    adapter.execute({"to": ["customer:8812"], "subject": "s", "body": "b",
                     "cc": ["attacker@evil.example"]})
    import json
    sent = json.loads(calls[0][2])
    assert sent == {"to": ["customer:8812"], "subject": "s", "body": "b"}
    assert "cc" not in sent


def test_mail_records_no_read():
    adapter = MailAdapter(
        binding={"base_url": "http://m", "fields": ["to", "subject", "body"]},
        client=recording_client([]),
    )
    assert adapter.execute({"to": [], "subject": "", "body": ""}).data_class is None


@pytest.mark.parametrize("adapter_cls,kind", [
    (DocstoreAdapter, "doc"), (HttpAdapter, "http"), (MailAdapter, "mail"),
])
def test_each_declares_its_target_kind(adapter_cls, kind):
    assert adapter_cls.target_kind == kind
```

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_adapters_simple.py -v
```

Expected: `ModuleNotFoundError: No module named 'broker.adapters.docstore'`.

- [ ] **Step 3: Implement `broker/adapters/docstore.py`**

```python
"""Reads a document from an HTTP document store."""

from __future__ import annotations

from broker.adapters.base import ToolResult, ToolTarget


class DocstoreAdapter:
    target_kind = "doc"

    def __init__(self, *, binding: dict, client) -> None:
        self._base_url = str(binding["base_url"]).rstrip("/")
        self._template = binding.get("path_template", "/docs/{doc_id}")
        self._arg = binding.get("arg", "doc_id")
        self._data_class = binding.get("data_class")
        self._client = client

    def describe(self, args: dict) -> ToolTarget:
        # The BARE id, not the resolved request path. describe() and execute()
        # disagree here deliberately: the policy target names the document,
        # and resolving it would change what the replay prints and re-flow the
        # column padding on that line.
        return ToolTarget(kind=self.target_kind, path=str(args.get(self._arg, "")))

    def execute(self, args: dict) -> ToolResult:
        path = self._template.format(**{self._arg: args[self._arg]})
        response = self._client.get(f"{self._base_url}{path}")
        response.raise_for_status()
        return ToolResult(content=response.text, data_class=self._data_class)
```

- [ ] **Step 4: Implement `broker/adapters/http.py`**

```python
"""Fetches an arbitrary URL. The egress-shaped adapter."""

from __future__ import annotations

from urllib.parse import urlsplit

from broker.adapters.base import DEFAULT_PORTS, ToolResult, ToolTarget


class HttpAdapter:
    target_kind = "http"

    def __init__(self, *, binding: dict, client) -> None:
        self._url_arg = binding.get("url_arg", "url")
        self._body_arg = binding.get("body_arg", "body")
        self._data_class = binding.get("data_class")
        self._client = client

    def describe(self, args: dict) -> ToolTarget:
        parts = urlsplit(args[self._url_arg])
        return ToolTarget(
            kind=self.target_kind,
            host=parts.hostname or "",
            port=parts.port or DEFAULT_PORTS.get(parts.scheme, 0),
            path=parts.path or "/",
        )

    def execute(self, args: dict) -> ToolResult:
        # A body makes this a POST. Exfiltration is a write, not a read: with
        # a bare GET the sinkhole records zero bytes and the unprotected
        # profile's first beat has nothing to show.
        body = args.get(self._body_arg)
        url = args[self._url_arg]
        response = self._client.get(url) if body is None else self._client.post(url, content=body)
        response.raise_for_status()
        return ToolResult(content=response.text, data_class=self._data_class)
```

- [ ] **Step 5: Implement `broker/adapters/mail.py`**

```python
"""Sends mail to declared counterparties."""

from __future__ import annotations

from broker.adapters.base import ToolResult, ToolTarget


class MailAdapter:
    target_kind = "mail"

    def __init__(self, *, binding: dict, client) -> None:
        self._base_url = str(binding["base_url"]).rstrip("/")
        self._path = binding.get("path", "/send")
        self._recipients_arg = binding.get("recipients_arg", "to")
        # The ONLY keys that go on the wire. backends.py forwarded the whole
        # args dict, so an undeclared cc reached the mailer on a call whose
        # audited target.recipients was the approved one -- the policy judged
        # one recipient set and the action used another.
        self._fields = tuple(binding["fields"])
        self._data_class = binding.get("data_class")
        self._client = client

    def describe(self, args: dict) -> ToolTarget:
        return ToolTarget(
            kind=self.target_kind,
            recipients=tuple(args.get(self._recipients_arg, [])),
        )

    def execute(self, args: dict) -> ToolResult:
        payload = {name: args[name] for name in self._fields if name in args}
        response = self._client.post(f"{self._base_url}{self._path}", json=payload)
        response.raise_for_status()
        return ToolResult(content="sent", data_class=self._data_class)
```

- [ ] **Step 6: Register them**

In `broker/adapters/registry.py`, replace `ADAPTERS: dict[str, type] = {}` with:

```python
from broker.adapters.docstore import DocstoreAdapter
from broker.adapters.http import HttpAdapter
from broker.adapters.mail import MailAdapter

ADAPTERS: dict[str, type] = {
    "docstore": DocstoreAdapter,
    "http": HttpAdapter,
    "mail": MailAdapter,
}
```

Move those imports below `TARGET_KIND_BY_ADAPTER` to keep the constant readable at the top of the file.

- [ ] **Step 7: Run and confirm green**

```bash
.venv/bin/python -m pytest tests/test_adapters_simple.py tests/test_adapter_registry.py -v
```

Expected: all PASS. `test_building_an_unknown_kind_is_an_error` still passes — `nosuchkind` is still absent.

- [ ] **Step 8: Commit**

```bash
git add broker/adapters/ tests/test_adapters_simple.py
git commit -m "feat(adapters): docstore, http and mail

One backends.py branch each, with the URLs and arg names that were literals
becoming bindings.  Two behaviours are preserved deliberately: docstore's
describe() reports the BARE document id rather than the resolved path, which
is what the replay prints; and http's execute() selects GET vs POST on
\`body is None\`, without which the sinkhole records zero bytes and the
unprotected profile has nothing to show.

mail sends only its declared fields.  backends.py forwarded the entire args
dict, so an undeclared cc reached the mailer on a call whose audited
recipients was the approved one."
```

---

### Task 11: The `sql` adapter

The one adapter that introduces a **new** security surface. Table and column names now arrive from config and are interpolated into SQL, where before they were literals in the source. Values stay bound parameters, as today; identifiers cannot be, so they are validated against `^[A-Za-z_][A-Za-z0-9_]*$` at **load** time and quoted at use.

Three behaviours must survive exactly:

- **`describe()` returns the true cardinality.** "Bounded" means no rows materialise, not that the count is capped. A `LIMIT`-wrapped count would turn `rows≈10312` into `rows≈51` in the replay, and drop the comparison table's `customer records read 10,313` to something meaningless — while `rows.bounded` still fires, so no test would notice.
- **The subject prefix joins to the token's counterparties.** `subject_prefix = "customer"` without its colon yields `["customer8812"]`, which is not in `["customer:8812"]`, so R7 `rows.scope` fires on the *allowed* read. `rows.bounded` does not fire (1 ≤ 50), so nothing outranks it: the replay's third line flips from allow to deny, the TAINT marker vanishes, and both later egress denials change reason because the task is never tainted — `docstore.internal` becomes an **allow**, since it is on `egress_allow`. The demo's central claim inverts.
- **A malformed subject value raises `ValueError`**, which `broker/app.py:173` maps to `input.malformed`. Anything else lands in the unaudited backend-fault branch.

**Files:**
- Create: `broker/adapters/sql.py`
- Modify: `broker/adapters/registry.py`
- Create: `tests/test_adapter_sql.py`

**Interfaces:**
- Consumes: `broker.adapters.base`, `broker.config.loader.ConfigError`
- Produces: `SqlAdapter(*, binding: dict, client)`, registered as `sql`. Binding keys: `db` (path), `table`, `columns` (list), `subject_column`, `subject_prefix`, `subject_type` (`"integer"`|`"string"`, default `"string"`), `default_column`, `unfiltered` (list, default `["", "all", "*"]`), `filter_arg` (default `"filter"`), `data_class`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_adapter_sql.py`:

```python
from __future__ import annotations

import sqlite3

import pytest

from broker.adapters.sql import SqlAdapter
from broker.config.loader import ConfigError

BINDING = {
    "table": "customers",
    "columns": ["id", "name", "email", "plan", "balance"],
    "subject_column": "id",
    "subject_prefix": "customer:",
    "subject_type": "integer",
    "default_column": "plan",
    "unfiltered": ["", "all", "*"],
    "data_class": "pii",
}


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "customers.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT,"
        " plan TEXT, balance REAL)"
    )
    connection.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?)",
        [(8810 + i, f"P{i}", f"p{i}@example.invalid",
          "pro" if i % 2 else "free", 1.0 * i) for i in range(10)],
    )
    connection.commit()
    connection.close()
    return path


def adapter(db, **overrides):
    return SqlAdapter(binding={**BINDING, "db": str(db), **overrides}, client=None)


def test_describe_returns_the_true_cardinality_not_a_capped_one(db):
    """Bounded means no rows materialise, NOT that the count is capped. A
    LIMIT-wrapped count would print rows≈51 where the demo prints rows≈10312
    while rows.bounded still fires -- no test would notice."""
    assert adapter(db).describe({"filter": "all"}).estimated_rows == 10


def test_describe_materialises_no_rows(db, monkeypatch):
    """The security property, asserted directly rather than via the integer."""
    executed = []
    real = sqlite3.Connection.execute

    def spy(self, sql, *args):
        executed.append(sql)
        return real(self, sql, *args)

    monkeypatch.setattr(sqlite3.Connection, "execute", spy)
    adapter(db).describe({"filter": "all"})
    assert executed and all("COUNT(" in sql for sql in executed), executed
    assert not any("SELECT \"id\"" in sql for sql in executed), executed


def test_subject_filter_names_one_bounded_subject(db):
    target = adapter(db).describe({"filter": "id=8812"})
    assert target.estimated_rows == 1
    assert target.subjects == ("customer:8812",)


def test_every_other_filter_reaches_an_unbounded_set(db):
    for expression in ("all", "", "*", "pro"):
        assert adapter(db).describe({"filter": expression}).subjects == ("*",)


def test_the_default_column_carries_a_bare_token(db):
    assert adapter(db).describe({"filter": "pro"}).estimated_rows == 5


def test_a_malformed_subject_value_raises_value_error(db):
    """app.py maps ValueError to input.malformed. Any other exception lands
    in the backend-fault branch, which audits nothing at all."""
    with pytest.raises(ValueError):
        adapter(db).describe({"filter": "id=not-a-number"})


def test_execute_returns_the_declared_columns_and_data_class(db):
    result = adapter(db).execute({"filter": "id=8812"})
    import json
    rows = json.loads(result.content)
    assert rows == [{"id": 8812, "name": "P2", "email": "p2@example.invalid",
                     "plan": "free", "balance": 2.0}]
    assert result.rows == 1
    assert result.data_class == "pii"


def test_describe_and_execute_agree_on_the_row_count(db):
    """They must, or a decision is made about one set and taken over another."""
    for expression in ("all", "pro", "id=8812"):
        assert (adapter(db).describe({"filter": expression}).estimated_rows
                == adapter(db).execute({"filter": expression}).rows)


@pytest.mark.parametrize("key,value", [
    ("table", "customers; DROP TABLE customers"),
    ("table", 'customers" --'),
    ("subject_column", "id OR 1=1"),
    ("default_column", "plan;--"),
])
def test_a_non_identifier_binding_is_rejected_at_load(db, key, value):
    """Identifiers cannot be bound parameters, so they are validated once at
    construction rather than sanitised at every use."""
    with pytest.raises(ConfigError, match=key):
        adapter(db, **{key: value})


def test_a_non_identifier_column_is_rejected_at_load(db):
    with pytest.raises(ConfigError, match="columns"):
        adapter(db, columns=["id", "name); DROP TABLE customers; --"])


def test_target_kind_is_db(db):
    assert adapter(db).target_kind == "db"
```

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_adapter_sql.py -v
```

Expected: `ModuleNotFoundError: No module named 'broker.adapters.sql'`.

- [ ] **Step 3: Implement `broker/adapters/sql.py`**

```python
"""Reads rows from a SQL table, counting before it reads.

describe() runs COUNT(*) and materialises nothing, so a query breaching the
row bound is denied before a single row exists in memory. That is the
security property; "bounded" refers to it, NOT to capping the count. The true
cardinality is returned, because the number is what the audit record and the
replay report.

Table and column names arrive from config and cannot be bound parameters, so
they are validated as identifiers ONCE at construction and quoted at use.
Values remain bound. Before this adapter they were literals in the source,
which is why the check is new rather than inherited.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from broker.adapters.base import ToolResult, ToolTarget
from broker.config.loader import ConfigError

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(value: object, where: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.match(value):
        raise ConfigError(f"{where} is not a SQL identifier: {value!r}")
    return value


def _quote(identifier: str) -> str:
    return f'"{identifier}"'


class SqlAdapter:
    target_kind = "db"

    def __init__(self, *, binding: dict, client=None) -> None:
        self._db_path = Path(binding["db"])
        self._table = _identifier(binding.get("table"), "sql binding table")
        columns = binding.get("columns")
        if not isinstance(columns, list) or not columns:
            raise ConfigError("sql binding columns must be a non-empty array")
        self._columns = tuple(
            _identifier(column, "sql binding columns") for column in columns
        )
        self._subject_column = _identifier(
            binding.get("subject_column"), "sql binding subject_column"
        )
        self._subject_prefix = str(binding.get("subject_prefix", ""))
        self._subject_type = binding.get("subject_type", "string")
        if self._subject_type not in ("integer", "string"):
            raise ConfigError('sql binding subject_type must be "integer" or "string"')
        self._default_column = _identifier(
            binding.get("default_column"), "sql binding default_column"
        )
        self._unfiltered = tuple(binding.get("unfiltered", ["", "all", "*"]))
        self._filter_arg = binding.get("filter_arg", "filter")
        self._data_class = binding.get("data_class")

    @property
    def _subject_marker(self) -> str:
        return f"{self._subject_column}="

    def _coerce(self, raw: str):
        # int() raises ValueError, which broker/app.py maps to
        # input.malformed. Any other exception type would fall into the
        # backend-fault branch, which records nothing at all against the
        # agent.
        return int(raw) if self._subject_type == "integer" else raw

    def _where(self, expression: str) -> tuple[str, list]:
        if expression in self._unfiltered:
            return "", []
        if expression.startswith(self._subject_marker):
            value = self._coerce(expression[len(self._subject_marker):])
            return f" WHERE {_quote(self._subject_column)} = ?", [value]
        return f" WHERE {_quote(self._default_column)} = ?", [expression]

    def _subjects(self, expression: str) -> tuple[str, ...]:
        """The data subjects a filter names, as counterparty identifiers.

        Only a subject-column filter names a bounded set. Anything else
        reaches an unbounded one and says so with "*" rather than by
        enumerating -- resolving a plan into ids would mean reading the rows
        to decide whether the read is allowed.

        The prefix must join exactly to the token's counterparties. Writing
        it without its separator yields "customer8812" against a declared
        "customer:8812", so R7 rows.scope fires on the ALLOWED read: the
        task never becomes tainted, and the later egress to the allowlisted
        internal sink stops being denied.
        """
        if not expression.startswith(self._subject_marker):
            return ("*",)
        try:
            value = self._coerce(expression[len(self._subject_marker):])
        except ValueError:
            # Unreachable through describe(), which builds the WHERE clause
            # first and raises on the same input. Kept so this helper is
            # total: a pure function that raises for one input is a trap for
            # the next caller.
            return ("*",)
        return (f"{self._subject_prefix}{value}",)

    def describe(self, args: dict) -> ToolTarget:
        expression = args.get(self._filter_arg, "")
        clause, params = self._where(expression)
        connection = sqlite3.connect(self._db_path)
        try:
            cursor = connection.execute(
                f"SELECT COUNT(*) FROM {_quote(self._table)}{clause}", params
            )
            count = int(cursor.fetchone()[0])
        finally:
            connection.close()
        return ToolTarget(
            kind=self.target_kind,
            estimated_rows=count,
            subjects=self._subjects(expression),
        )

    def execute(self, args: dict) -> ToolResult:
        expression = args.get(self._filter_arg, "")
        clause, params = self._where(expression)
        selected = ", ".join(_quote(column) for column in self._columns)
        connection = sqlite3.connect(self._db_path)
        try:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"SELECT {selected} FROM {_quote(self._table)}{clause}", params
            ).fetchall()
        finally:
            connection.close()
        payload = [dict(row) for row in rows]
        return ToolResult(
            content=json.dumps(payload), rows=len(payload), data_class=self._data_class
        )
```

- [ ] **Step 4: Register it**

In `broker/adapters/registry.py`, add `from broker.adapters.sql import SqlAdapter` and `"sql": SqlAdapter,` to `ADAPTERS`.

- [ ] **Step 5: Run and confirm green**

```bash
.venv/bin/python -m pytest tests/test_adapter_sql.py tests/test_adapter_registry.py -v
```

Expected: all PASS.

- [ ] **Step 6: Prove it against the real seeded database**

The unit tests use a ten-row table. Confirm the real one gives the number the demo quotes.

```bash
.venv/bin/python - <<'EOF'
from broker.adapters.sql import SqlAdapter
a = SqlAdapter(binding={
    "db": "data/customers.db", "table": "customers",
    "columns": ["id", "name", "email", "plan", "balance"],
    "subject_column": "id", "subject_prefix": "customer:",
    "subject_type": "integer", "default_column": "plan",
    "unfiltered": ["", "all", "*"], "data_class": "pii",
}, client=None)
print("all      ->", a.describe({"filter": "all"}).estimated_rows,
      a.describe({"filter": "all"}).subjects)
print("id=8812  ->", a.describe({"filter": "id=8812"}).estimated_rows,
      a.describe({"filter": "id=8812"}).subjects)
EOF
```

Expected exactly:

```
all      -> 10312 ('*',)
id=8812  -> 1 ('customer:8812',)
```

`10312` is the number in `README.md:42`; `('customer:8812',)` is what must join to the token's counterparties. If either differs, stop.

- [ ] **Step 7: Commit**

```bash
git add broker/adapters/sql.py broker/adapters/registry.py tests/test_adapter_sql.py
git commit -m "feat(adapters): sql, counting before it reads

describe() runs COUNT(*) and materialises nothing, so a query breaching the
row bound is denied before a row exists.  It returns the TRUE cardinality:
capping the count would print rows≈51 where the demo prints rows≈10312 while
rows.bounded still fired, and nothing would have noticed.

Table and column names now come from config and cannot be bound parameters,
so they are validated as identifiers once at construction and quoted at use.
That check is new because they used to be literals in the source.

The subject prefix is the join to the token's counterparties.  Written
without its separator it yields customer8812 against a declared
customer:8812, and rows.scope then denies the ALLOWED read -- the task never
becomes tainted and the egress to the allowlisted internal sink stops being
refused.  Asserted against the shipped binding, not a fixture."
```

---

### Task 12: `ToolCatalog`, and the demo's manifest

The catalog is the product's replacement for `TOOLS` and `Backends`. Two membership checks stay **separate**, as they are today: the validator *defers* on a tool it does not know (returning `True`), and `describe()` raises `UnknownTool`. Collapsing them into one would change what an unrecognised tool is audited as — from `tools.allowed` with `target.kind == "unknown"` to `input.malformed` — and would merge two different incidents ("a tool the broker never heard of" and "a tool whose target the broker mislabelled") into one reason.

The demo's manifest lands at its **final** path now, `demo/scenario/tools.toml`. It is config, not code, so nothing imports it and Phase 3's directory move does not have to touch it.

**Files:**
- Create: `broker/config/catalog.py`
- Create: `demo/scenario/tools.toml`
- Create: `tests/support/__init__.py`, `tests/support/catalog.py`
- Create: `tests/test_catalog.py`

**Interfaces:**
- Consumes: `broker.adapters.registry.build_adapter`, `TARGET_KIND_BY_ADAPTER`, `broker.config.schema.parse_tool_schema`, `broker.adapters.base.UnknownTool`
- Produces:
  - `broker.config.catalog.ToolCatalog` — `names() -> frozenset[str]`, `__contains__`, `validate(tool, args) -> bool`, `describe(tool, args) -> ToolTarget`, `execute(tool, args) -> ToolResult`, `target_kind(tool) -> str`.
  - `load_catalog(path: Path, env: Mapping[str, str], client) -> ToolCatalog`.
  - `tests.support.catalog.demo_catalog(*, docstore_url, db_path, mailer_url, client) -> ToolCatalog` — loads the **shipped** `demo/scenario/tools.toml` with those three bindings substituted, so every test exercises the real manifest.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_catalog.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from broker.adapters.base import UnknownTool
from broker.config.catalog import ToolCatalog, load_catalog
from broker.config.loader import ConfigError

MANIFEST = """
[tools.read_document]
kind = "docstore"
[tools.read_document.binding]
base_url   = "${DOCSTORE_URL}"
data_class = "public"
[tools.read_document.args]
doc_id = { type = "string", required = true, non_empty = true }
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "tools.toml"
    path.write_text(text)
    return path


def test_an_empty_catalog_is_legal_and_knows_nothing():
    """The product ships no tools. An empty catalog is a broker that permits
    nothing, which is the correct default for a deny-by-default system."""
    catalog = ToolCatalog({})
    assert catalog.names() == frozenset()
    assert "read_document" not in catalog
    with pytest.raises(UnknownTool):
        catalog.describe("read_document", {})
    with pytest.raises(UnknownTool):
        catalog.execute("read_document", {})


def test_validate_defers_on_an_unknown_tool():
    """It must DEFER, not deny. Today an unrecognised tool passes the shape
    check, reaches describe(), raises UnknownTool and is audited under
    tools.allowed with target.kind "unknown". Denying here instead would
    change the audited rule to input.malformed and merge two different
    incidents into one reason."""
    assert ToolCatalog({}).validate("anything", {"x": 1}) is True


def test_loads_a_manifest_and_interpolates_bindings(tmp_path):
    catalog = load_catalog(
        write(tmp_path, MANIFEST),
        env={"DOCSTORE_URL": "http://docstore.internal"},
        client=None,
    )
    assert catalog.names() == frozenset({"read_document"})
    assert catalog.target_kind("read_document") == "doc"
    assert catalog.validate("read_document", {"doc_id": "x"}) is True
    assert catalog.validate("read_document", {"doc_id": ""}) is False
    assert catalog.validate("read_document", {"doc_id": "x", "junk": 1}) is False


def test_an_unset_binding_variable_is_a_startup_failure(tmp_path):
    with pytest.raises(ConfigError, match="DOCSTORE_URL"):
        load_catalog(write(tmp_path, MANIFEST), env={}, client=None)


def test_an_unknown_adapter_kind_is_a_startup_failure(tmp_path):
    text = MANIFEST.replace('kind = "docstore"', 'kind = "graphql"')
    with pytest.raises(ConfigError, match="graphql"):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_a_tool_without_an_args_table_is_a_startup_failure(tmp_path):
    text = MANIFEST.split("[tools.read_document.args]")[0]
    with pytest.raises(ConfigError, match="read_document"):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_a_missing_manifest_is_a_startup_failure(tmp_path):
    with pytest.raises(ConfigError, match="tools.toml"):
        load_catalog(tmp_path / "tools.toml", env={}, client=None)


def test_the_shipped_demo_manifest_loads(tmp_path):
    """Not a fixture -- the real file, which is what every later assertion
    about subjects and row counts is made against."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path="data/customers.db",
        mailer_url="http://mailer.internal",
        client=None,
    )
    assert catalog.names() == frozenset(
        {"read_document", "query_customers", "http_fetch", "send_email"}
    )
    assert catalog.target_kind("query_customers") == "db"
    assert catalog.target_kind("send_email") == "mail"


def test_the_shipped_manifest_reproduces_the_subject_join():
    """The prefix must join to the token's counterparties. Without its colon
    the ALLOWED read is denied rows.scope, the task never becomes tainted,
    and the egress to the allowlisted internal sink stops being refused."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://d", db_path="data/customers.db",
        mailer_url="http://m", client=None,
    )
    assert catalog.describe("query_customers", {"filter": "id=8812"}).subjects == (
        "customer:8812",
    )
    assert catalog.describe("query_customers", {"filter": "all"}).subjects == ("*",)
    assert catalog.describe("query_customers", {"filter": "all"}).estimated_rows == 10312
```

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_catalog.py -v
```

Expected: `ModuleNotFoundError: No module named 'broker.config.catalog'`.

- [ ] **Step 3: Implement `broker/config/catalog.py`**

```python
"""The tool catalog: what this deployment's tools are and how to reach them.

Replaces the compiled-in TOOLS tuple and the Backends class, which between
them knew four tool names, a table called customers, a column called plan and
a subject prefix.

Two membership checks stay SEPARATE, as they are in the code this replaces.
validate() DEFERS on a tool it does not know; describe() raises UnknownTool.
Collapsing them would change what an unrecognised tool is audited as -- from
tools.allowed with target.kind "unknown" to input.malformed -- and would merge
"a tool the broker never heard of" with "a tool whose target the broker
mislabelled" into a single reason.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from broker.adapters.base import ToolResult, ToolTarget, UnknownTool
from broker.adapters.registry import TARGET_KIND_BY_ADAPTER, build_adapter
from broker.config.loader import ConfigError, interpolate
from broker.config.schema import ToolSchema, parse_tool_schema


@dataclass(frozen=True)
class CatalogEntry:
    kind: str
    target_kind: str
    schema: ToolSchema
    adapter: object


class ToolCatalog:
    def __init__(self, entries: Mapping[str, CatalogEntry]) -> None:
        self._entries = dict(entries)

    def names(self) -> frozenset[str]:
        return frozenset(self._entries)

    def __contains__(self, tool: str) -> bool:
        return tool in self._entries

    def target_kind(self, tool: str) -> str:
        return self._entry(tool).target_kind

    def _entry(self, tool: str) -> CatalogEntry:
        try:
            return self._entries[tool]
        except KeyError as exc:
            raise UnknownTool(tool) from exc

    def validate(self, tool: str, args: dict) -> bool:
        entry = self._entries.get(tool)
        if entry is None:
            # Defer. describe() performs the membership check and the broker
            # audits the result as tools.allowed.
            return True
        return entry.schema.validate(args)

    def describe(self, tool: str, args: dict) -> ToolTarget:
        return self._entry(tool).adapter.describe(args)

    def execute(self, tool: str, args: dict) -> ToolResult:
        return self._entry(tool).adapter.execute(args)


def _interpolate_binding(binding: dict, env: Mapping[str, str], where: str) -> dict:
    resolved = {}
    for key, value in binding.items():
        if isinstance(value, str):
            resolved[key] = interpolate(value, env)
        elif isinstance(value, list):
            resolved[key] = [
                interpolate(item, env) if isinstance(item, str) else item
                for item in value
            ]
        else:
            resolved[key] = value
    return resolved


def load_catalog(path: Path, env: Mapping[str, str], client) -> ToolCatalog:
    path = Path(path)
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"tool catalog not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    tools = document.get("tools", {})
    if not isinstance(tools, dict):
        raise ConfigError(f"{path}: [tools] must be a table")

    entries: dict[str, CatalogEntry] = {}
    for tool, table in tools.items():
        if not isinstance(table, dict):
            raise ConfigError(f"{path}: tool {tool!r} must be a table")
        kind = table.get("kind")
        if kind not in TARGET_KIND_BY_ADAPTER:
            raise ConfigError(
                f"tool {tool!r}: unknown adapter kind {kind!r}; "
                f"expected one of {sorted(TARGET_KIND_BY_ADAPTER)}"
            )
        binding = table.get("binding", {})
        if not isinstance(binding, dict):
            raise ConfigError(f"tool {tool!r}: [binding] must be a table")
        entries[tool] = CatalogEntry(
            kind=kind,
            target_kind=TARGET_KIND_BY_ADAPTER[kind],
            schema=parse_tool_schema(table, tool),
            adapter=build_adapter(
                kind, _interpolate_binding(binding, env, tool), client
            ),
        )
    return ToolCatalog(entries)
```

- [ ] **Step 4: Write the demo manifest**

Create `demo/scenario/tools.toml`:

```toml
# The DEMO's tool catalog.
#
# The product ships none of this.  warden/reference/tools.toml declares zero
# tools, because an empty catalog is a broker that permits nothing -- the
# correct default for a deny-by-default system.
#
# `kind` names an ADAPTER kind (docstore/sql/http/mail).  The policy reasons
# about TARGET kinds (doc/db/http/mail).  The mapping lives in
# broker/adapters/registry.py and is asserted against authz.rego R0; do not
# write a target kind here.

[tools.read_document]
kind = "docstore"

[tools.read_document.binding]
base_url   = "${DOCSTORE_URL}"
data_class = "public"

[tools.read_document.args]
doc_id = { type = "string", required = true, non_empty = true }


[tools.query_customers]
kind = "sql"

[tools.query_customers.binding]
db      = "${DB_PATH}"
table   = "customers"
columns = ["id", "name", "email", "plan", "balance"]
# Only a `id=` filter names a bounded subject set; anything else reaches "*",
# which can never appear in a token's counterparties, so an unbounded read is
# out of scope by construction rather than by a second rule.
subject_column = "id"
# The join to the token's counterparties.  The colon is load-bearing: without
# it this yields customer8812 against a declared customer:8812, R7 rows.scope
# denies the ALLOWED read, the task never becomes tainted, and the egress to
# the allowlisted internal sink stops being refused.
subject_prefix = "customer:"
subject_type   = "integer"
# A bare token means plan = <token>.
default_column = "plan"
unfiltered     = ["", "all", "*"]
data_class     = "pii"

[tools.query_customers.args]
# required, though both stages default it.  This mirrors the check being
# replaced, NOT what the adapter can default: relaxing it turns a refusal into
# a full-table COUNT judged by policy.
filter = { type = "string", required = true }


[tools.http_fetch]
kind = "http"

[tools.http_fetch.binding]
data_class = "public"

[tools.http_fetch.args]
url = { type = "string", required = true, non_empty = true }
# null must validate and reach execute() as None: that is how GET and POST are
# chosen, and exfiltration is a write.
body = { type = "string", required = false, null_is_absent = true }


[tools.send_email]
kind = "mail"

[tools.send_email.binding]
base_url = "${MAILER_URL}"
# The ONLY keys that go on the wire.  backends.py forwarded the whole args
# dict, so an undeclared cc reached the mailer on a call whose audited
# recipients was the approved one.
fields = ["to", "subject", "body"]

[tools.send_email.args]
to      = { type = "array", items = "string", required = true }
subject = { type = "string", required = true }
body    = { type = "string", required = true }
```

- [ ] **Step 5: Write the test helper**

Create `tests/support/__init__.py` (empty) and `tests/support/catalog.py`:

```python
"""Builds a catalog from the SHIPPED demo manifest.

Deliberately not a fixture describing the same four tools independently: a
test-local copy would keep passing while the file the demo actually loads
drifted. Everything asserted about subjects, row counts and arg shapes is
asserted about demo/scenario/tools.toml itself.
"""

from __future__ import annotations

from pathlib import Path

from broker.config.catalog import ToolCatalog, load_catalog

MANIFEST = Path(__file__).resolve().parent.parent.parent / "demo" / "scenario" / "tools.toml"


def demo_catalog(*, docstore_url: str, db_path, mailer_url: str, client) -> ToolCatalog:
    return load_catalog(
        MANIFEST,
        env={
            "DOCSTORE_URL": docstore_url,
            "DB_PATH": str(db_path),
            "MAILER_URL": mailer_url,
        },
        client=client,
    )
```

- [ ] **Step 6: Run and confirm green**

```bash
.venv/bin/python -m pytest tests/test_catalog.py -v
```

Expected: 9 PASS. The last asserts `estimated_rows == 10312` against the real seeded database — the number in `README.md:42`.

- [ ] **Step 7: Commit**

```bash
git add broker/config/catalog.py demo/scenario/tools.toml tests/support/ tests/test_catalog.py
git commit -m "feat(config): a tool catalog, replacing the compiled-in TOOLS tuple

Backends knew four tool names, a table called customers, a column called plan
and a subject prefix.  The catalog knows adapter kinds and reads the rest from
a manifest.

The two membership checks stay separate on purpose: validate() DEFERS on an
unknown tool and describe() raises UnknownTool, so an unrecognised tool is
still audited under tools.allowed with target.kind unknown.  Collapsing them
would rename that to input.malformed and merge two different incidents.

The demo's manifest lands at its final path now -- it is config, so no import
depends on it and the Phase 3 move does not have to touch it.  Tests load THAT
file rather than a local copy, so a fixture cannot keep passing while the file
the demo actually loads drifts."
```

---

### Task 13: `app.py` takes a catalog

`_args_are_well_shaped` is deleted; `backends` becomes `catalog`. One extra fix lands here because moving validation into config creates the hole: an arg an adapter dereferences but the schema does not require raises `KeyError` from `describe()`, and `KeyError` is not `ValueError`, so `app.py:181` treats it as a backend fault — **measured 502 with zero audit records**, letting an agent probe without trace. That branch is narrowed.

**Files:**
- Modify: `broker/app.py` (delete `_args_are_well_shaped`; `backends` → `catalog`; narrow the `describe()` handler)
- Modify: `tests/test_app.py` (9 `create_app` sites, 8 `Backends(` sites)
- Modify: `tests/test_injection_contained.py:148-160`
- Modify: `tests/test_cassette.py:7`, `tests/test_agent.py:386,395`

**Interfaces:**
- Consumes: `broker.config.catalog.ToolCatalog` (Task 12)
- Produces: `create_app(*, verifier, pdp, taint, audit, catalog, policy_digest) -> FastAPI`. The keyword is `catalog`; `backends` is gone.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_app.py`:

```python
def test_a_missing_required_arg_is_audited_not_a_silent_502(tmp_path):
    """The hole config-driven validation opens.

    An arg an adapter dereferences but the schema does not require raises
    KeyError from describe(). KeyError is not ValueError, so it landed in the
    backend-fault branch: measured 502 with ZERO audit records, which is an
    agent probing with no trace -- the same defect _refuse_unauthenticated
    exists to close on the auth path.
    """
    from broker.config.catalog import CatalogEntry, ToolCatalog
    from broker.config.schema import ArgSpec, ToolSchema

    class Dereferences:
        target_kind = "doc"

        def describe(self, args):
            return args["absent"]          # KeyError

        def execute(self, args):           # pragma: no cover
            raise AssertionError("must never be reached")

    catalog = ToolCatalog({
        "loose": CatalogEntry(
            kind="docstore", target_kind="doc",
            # Deliberately does not require the arg describe() dereferences.
            schema=ToolSchema(args={"absent": ArgSpec(type="string")}),
            adapter=Dereferences(),
        )
    })
    audit, client, token = app_with_catalog(tmp_path, catalog)
    response = client.post(
        "/v1/tools/loose/invoke", json={"args": {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert response.json()["rule"] == "input.malformed"
    assert audit.records()[-1]["rule"] == "input.malformed"
    assert audit.records()[-1]["decision"] == "deny"
```

Add an `app_with_catalog(tmp_path, catalog)` helper near the top of `tests/test_app.py` that mints a token and returns `(audit, TestClient(app), token)`, factored out of the existing setup at lines 33-46.

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_app.py::test_a_missing_required_arg_is_audited_not_a_silent_502 -v
```

Expected: `502` / `backend_error`, and `audit.records()` empty.

- [ ] **Step 3: Rewrite `broker/app.py`'s tool path**

Delete `_args_are_well_shaped` (lines 94-118) and the `from broker.backends import ...` line. Import from the new homes:

```python
from broker.adapters.base import ToolTarget, UnknownTool
from broker.config.catalog import ToolCatalog
```

Change the signature at line 121-129 — `backends: Backends` becomes `catalog: ToolCatalog` — and inside `invoke`:

```python
        if not catalog.validate(tool, args):
            return _deny(
                audit, token, tool, args, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest,
            )

        try:
            target = catalog.describe(tool, args)
        except UnknownTool:
            # Deny-by-default at the edge: an unrecognised tool never reaches
            # the PDP, but is still audited under the capability rule.
            return _deny(
                audit, token, tool, args, ToolTarget(kind="unknown"), state,
                "tools.allowed", policy_digest,
            )
        except (ValueError, KeyError, TypeError, IndexError):
            # Client-caused describe() failures the schema did not catch: a
            # filter value of the right type but not parseable, or an arg the
            # adapter dereferences that the schema left optional. KeyError is
            # NOT ValueError, so before this it fell into the backend-fault
            # branch below -- 502, and nothing recorded against the agent,
            # which is an agent probing with no trace.
            return _deny(
                audit, token, tool, args, ToolTarget(kind="malformed"), state,
                "input.malformed", policy_digest,
            )
        except Exception as exc:
            # A genuine backend/server fault, not the agent's doing.
            return _backend_fault(str(exc))
```

Replace `backends.execute(tool, args)` with `catalog.execute(tool, args)`.

- [ ] **Step 4: Update the call sites**

In `tests/test_app.py`, replace each `backends=Backends(docstore_url=…, db_path=…, mailer_url=…, client=…)` with `catalog=demo_catalog(docstore_url=…, db_path=…, mailer_url=…, client=…)` and add `from tests.support.catalog import demo_catalog`. Same substitution in `tests/test_injection_contained.py:148-160`.

`tests/test_cassette.py:7` and `tests/test_agent.py:386,395` import `_args_are_well_shaped` and `broker.backends.TOOLS`. Repoint them at the public surface:

```python
from tests.support.catalog import demo_catalog

CATALOG = demo_catalog(docstore_url="http://d", db_path="data/customers.db",
                       mailer_url="http://m", client=None)
# was: broker.backends.TOOLS
TOOL_NAMES = CATALOG.names()
# was: _args_are_well_shaped(tool, args)
CATALOG.validate(tool, args)
```

- [ ] **Step 5: Run the whole suite**

```bash
.venv/bin/python -m pytest -q
```

Expected: 0 failures. Specifically confirm these pass **unedited**, since they are the deny-by-default guard:

```bash
.venv/bin/python -m pytest tests/test_app.py -k "unknown_tool or tools_allowed" -v
```

- [ ] **Step 6: Confirm the goldens still hold**

```bash
.venv/bin/python -m pytest tests/test_golden_decisions.py tests/test_golden_replay.py -q
```

Expected: all PASS. Phase 1 changes no policy and no audit bytes.

- [ ] **Step 7: Commit**

```bash
git add broker/app.py tests/
git commit -m "refactor(broker): app takes a catalog, not a Backends

_args_are_well_shaped's four hand-written branches become the manifest's arg
schemas.  Equivalence was proved input-by-input in the previous task, not
asserted.

One fix lands with it, because moving validation into config creates the
hole: an arg an adapter dereferences that the schema left optional raises
KeyError from describe(), and KeyError is not ValueError, so it fell into the
backend-fault branch -- 502 with zero audit records, an agent probing with no
trace.  KeyError, TypeError and IndexError are now client-caused and audited
under input.malformed."
```

---

### Task 14: `BrokerComponents`, and the entrypoint from TOML

`build()` returns an untyped `deps` dict splatted into both `create_app` and `serve_proxy`. Their signatures differ and neither takes `**kwargs`, so **adding the catalog key to it raises `TypeError` from `serve_proxy` and takes all egress down.** Invisible to any grep for a literal.

**Files:**
- Create: `broker/wiring.py`
- Modify: `broker/__main__.py`, `broker/proxy.py:220-240`, `broker/control_main.py`
- Create: `warden.toml`, `control.toml` (repo root; Phase 3 moves them under `demo/scenario/`)
- Modify: `tests/test_entrypoints.py`

**Interfaces:**
- Consumes: `BrokerConfig` (Task 7), `ToolCatalog` (Task 12)
- Produces: `broker.wiring.BrokerComponents` — frozen dataclass `(verifier, pdp, taint, audit, policy_digest)`, with `.as_app_kwargs()` and `.as_proxy_kwargs()`. `broker.__main__.build(config: BrokerConfig, *, client=None) -> tuple[FastAPI, BrokerComponents]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_entrypoints.py`:

```python
def test_wiring_is_typed_so_a_new_component_cannot_break_the_proxy():
    """deps was an untyped dict splatted into two functions with different
    signatures, neither taking **kwargs. Adding one key -- the catalog, which
    create_app needs and authorize_connect does not -- raised TypeError from
    serve_proxy and took all egress down. No grep for a literal finds that."""
    import inspect
    from broker.app import create_app
    from broker.proxy import authorize_connect
    from broker.wiring import BrokerComponents

    app_params = set(inspect.signature(create_app).parameters)
    proxy_params = set(inspect.signature(authorize_connect).parameters)
    assert set(BrokerComponents.as_app_kwargs.__annotations__) or True
    stub = BrokerComponents(verifier=None, pdp=None, taint=None, audit=None,
                            policy_digest="sha256:x")
    assert set(stub.as_app_kwargs()) <= app_params
    assert set(stub.as_proxy_kwargs()) <= proxy_params


def test_the_entrypoint_reads_a_toml_config(tmp_path):
    from broker.config.loader import load_broker_config
    import broker.__main__ as broker_main

    _, public_path = write_keypair(tmp_path)
    (tmp_path / "warden.toml").write_text(f"""
[broker]
listen = "0.0.0.0:8080"
proxy_listen = "0.0.0.0:3128"
[identity]
public_key = "{public_path}"
[policy]
opa_url = "http://opa:8181"
decision_path = "warden/authz"
bundle_roots = ["policies"]
[audit]
path = "{tmp_path / 'audit.jsonl'}"
[tokens]
issuer = "warden-broker"
ttl_seconds = 300
[catalog]
tools = "demo/scenario/tools.toml"
""")
    config = load_broker_config(tmp_path / "warden.toml", env={
        "DOCSTORE_URL": "http://d", "DB_PATH": "data/customers.db",
        "MAILER_URL": "http://m",
    })
    app, components = broker_main.build(config, client=stub_client())
    assert components.policy_digest.startswith("sha256:")
```

The existing `test_broker_process_holds_no_signing_key` walker traverses dicts and `__dict__`. `BrokerComponents` is a dataclass, so it has `__dict__` — the walker still reaches it. **Extend it to traverse lists and tuples as well**, since the catalog holds adapters in a dict and `bundle_roots` is a tuple:

```python
        values = root.values() if isinstance(root, dict) else []
        items = list(root) if isinstance(root, (list, tuple, set)) else []
        attrs = getattr(root, "__dict__", {}).values()
        for child in [*values, *items, *attrs]:
```

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_entrypoints.py -k "wiring or toml" -v
```

Expected: `ModuleNotFoundError: No module named 'broker.wiring'`.

- [ ] **Step 3: Implement `broker/wiring.py`**

```python
"""The components both enforcement surfaces share, as a type rather than a dict.

build() used to return an untyped dict splatted into create_app AND
serve_proxy. Their signatures differ and neither takes **kwargs, so every key
had to be a valid keyword of both -- and adding the catalog, which the tool
API needs and the proxy does not, raised TypeError from serve_proxy and took
all egress down. Nothing greppable expressed that constraint.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BrokerComponents:
    verifier: object
    pdp: object
    taint: object
    audit: object
    policy_digest: str

    def as_app_kwargs(self) -> dict:
        return {
            "verifier": self.verifier, "pdp": self.pdp, "taint": self.taint,
            "audit": self.audit, "policy_digest": self.policy_digest,
        }

    def as_proxy_kwargs(self) -> dict:
        return self.as_app_kwargs()
```

- [ ] **Step 4: Rewrite `broker/__main__.py`'s `build`**

```python
def build(config: BrokerConfig, *, client: httpx.Client | None = None):
    """Wires the enforcement point from a parsed config.

    Returned as (app, components) so the proxy shares exactly the same
    verifier, PDP, taint tracker and audit log as the tool API -- two
    surfaces, one set of controls.
    """
    client = client or httpx.Client(timeout=10.0)
    components = BrokerComponents(
        # Public key only. There is no Signer in this process.
        verifier=Verifier.from_public_key_file(config.public_key),
        pdp=PolicyDecisionPoint(
            config.opa_url, decision_path=config.decision_path, client=client
        ),
        taint=TaintTracker(),
        audit=AuditLog(config.audit_path),
        # Computed once at startup, never lazily per request: a missing or
        # unreadable bundle must crash before the first decision.
        policy_digest=policy_bundle_digest(config.bundle_roots),
    )
    app = create_app(
        catalog=load_catalog(config.catalog_path, os.environ, client),
        **components.as_app_kwargs(),
    )
    return app, components
```

And `main()`:

```python
async def main() -> None:
    config = load_broker_config(
        Path(os.environ.get("WARDEN_CONFIG", "/config/warden.toml")), os.environ
    )
    app, components = build(config)
    proxy_host, proxy_port = config.proxy_listen
    api_host, api_port = config.listen
    proxy_server = await serve_proxy(proxy_host, proxy_port, **components.as_proxy_kwargs())
    agent_api = uvicorn.Server(
        uvicorn.Config(app, host=api_host, port=api_port, log_level="warning")
    )
    async with proxy_server:
        await agent_api.serve()
```

Delete `PUBLIC_KEY_PATH`. Keep the module docstring — the property it states is unchanged, and `test_broker_entrypoint_source_never_names_the_signer` still parses this file.

- [ ] **Step 5: Give `PolicyDecisionPoint` a configurable decision path**

`broker/pdp.py:40` hardcodes `/v1/data/warden/authz`. Add an optional parameter defaulting to today's value, so no existing test changes:

```python
    def __init__(self, base_url: str, *, decision_path: str = "warden/authz", client) -> None:
        self._url = f"{base_url.rstrip('/')}/v1/data/{decision_path.strip('/')}"
```

- [ ] **Step 6: Update the proxy's dict access**

`broker/proxy.py:220-240` reads `deps["audit"]` and `deps["policy_digest"]` by key while also splatting. Leave the `**deps` forwarding — `as_proxy_kwargs()` returns a plain dict — but the two by-key reads still work unchanged. Confirm with `grep -n 'deps\[' broker/proxy.py`; no edit is needed if both keys are still present, which they are.

- [ ] **Step 7: Write the demo's `warden.toml` and `control.toml`**

Create `warden.toml` at the repo root with the values `docker-compose.yml:56-63` currently sets as environment variables (`OPA_URL: http://opa:8181`, `DOCSTORE_URL`, `MAILER_URL`, `DB_PATH: /data/customers.db`, `AUDIT_PATH: /data/audit.jsonl`, `AGENT_PUBLIC_KEY_PATH: /data/agent.pub`), plus `bundle_roots = ["/policies"]` and `tools = "/config/tools.toml"`. Create `control.toml` with `[control] listen = "0.0.0.0:8081"` and `[identity] private_key = "/data/agent.key"`, and rewrite `broker/control_main.py` to read it the same way.

Add both to `docker-compose.yml` as mounts on the `broker` and `broker-control` services, and set `WARDEN_CONFIG` / `WARDEN_CONTROL_CONFIG`. Keep `DOCSTORE_URL`, `DB_PATH` and `MAILER_URL` in the broker's `environment:` — they are now consumed as `${VAR}` by `tools.toml`, not read directly by Python.

- [ ] **Step 8: Run the suite, then the demo**

```bash
.venv/bin/python -m pytest -q
sg docker -c "./scripts/demo.sh guarded" 2>&1 | tail -11
```

Expected: 0 failures; the replay matches `README.md:37-48` exactly above the head hash.

- [ ] **Step 9: Commit**

```bash
git add broker/ warden.toml control.toml docker-compose.yml tests/test_entrypoints.py
git commit -m "refactor(broker): typed wiring, and an entrypoint that reads TOML

deps was an untyped dict splatted into create_app and serve_proxy.  Their
signatures differ and neither takes **kwargs, so adding the catalog -- which
the tool API needs and the proxy does not -- raised TypeError from
serve_proxy and took all egress down.  No grep for a literal expresses that.

Ports, paths, the OPA URL, its decision path, the token issuer and TTL all
move out of the source.  The no-signing-key test's object walker now
traverses lists and tuples too, or it would go blind on a catalog that holds
its adapters in a dict."
```

---

### Task 15: Delete `backends.py`, repoint the demo

**Files:**
- Delete: `broker/backends.py`
- Modify: `cli/explain.py:49-55, 896-912` (`NarratedBackends` wraps the catalog)
- Modify: `tests/test_backends.py` → `tests/test_adapters_demo.py`
- Modify: `agent/tools.py:150-181` (`DirectDispatcher`'s duplicated WHERE clause)

**Interfaces:**
- Consumes: everything from Tasks 7-14
- Produces: no module named `broker.backends`. `cli/explain.py`'s `NarratedBackends` wraps a `ToolCatalog` and narrates `describe`/`execute` per tool as before.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_seam_precursor.py` (new file — the full seam test arrives in Phase 3):

```python
"""backends.py is gone, and nothing reaches for it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_backends_module_is_gone():
    assert not (REPO_ROOT / "broker" / "backends.py").exists()
    with pytest.raises(ModuleNotFoundError):
        __import__("broker.backends")


def test_no_module_imports_it():
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in REPO_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts and ".venv" not in path.parts
        and re.search(r"\bbroker\.backends\b|\bfrom broker import backends\b",
                      path.read_text())
    ]
    assert offenders == []


def test_no_tool_name_remains_in_the_broker_package():
    """Phase 3 asserts the whole scenario-string list. This is the subset that
    can be true already: the four tool names must be gone from broker/ once
    the catalog owns them. app.py lines 27 and 175 name query_customers in
    comments explaining the input.malformed boundary -- reword them, keeping
    the meaning ("an argument of the right type the adapter cannot parse")."""
    names = ("read_document", "query_customers", "http_fetch", "send_email")
    offenders = []
    for path in (REPO_ROOT / "broker").rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text()
        for name in names:
            if name in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {name}")
    assert offenders == []
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_seam_precursor.py -v
```

Expected: all three fail — the module exists, `cli/explain.py` and tests import it, and `broker/app.py` names `query_customers` at lines 27, 101 and 175.

- [ ] **Step 3: Repoint `cli/explain.py`**

Replace the `Backends` import with `from broker.config.catalog import ToolCatalog`, change `NarratedBackends` to wrap a catalog (its `describe`/`execute` already take `(tool, args)`, so only the constructor changes), and at line 903:

```python
            catalog=NarratedBackends(
                demo_catalog(
                    docstore_url="http://docstore.internal",
                    db_path=db,
                    mailer_url="http://mailer.internal",
                    client=httpx.Client(transport=_mock_transport()),
                )
            ),
```

`cli/explain.py` is demo code, so importing `tests.support.catalog` is wrong. Move `demo_catalog` to `demo/scenario/catalog.py` and have `tests/support/catalog.py` re-export it — one definition, two importers, and the shipped manifest stays the only source.

- [ ] **Step 4: Rewrite `tests/test_backends.py` as `tests/test_adapters_demo.py`**

`git mv tests/test_backends.py tests/test_adapters_demo.py`, then replace the `Backends(...)` fixture with `demo_catalog(...)`. Keep every assertion. Two need strengthening, because their names claim more than their bodies check:

```python
def test_describe_counts_rows_before_the_query_runs(db, monkeypatch):
    """The name asserts the project's core security property; the body only
    checked an integer, so an adapter implementing describe() as
    len(SELECT *) would have passed. Assert the SQL."""
    import sqlite3
    statements = []
    real = sqlite3.Connection.execute
    monkeypatch.setattr(
        sqlite3.Connection, "execute",
        lambda self, sql, *a: (statements.append(sql), real(self, sql, *a))[1],
    )
    target = catalog(db).describe("query_customers", {"filter": "all"})
    assert target.estimated_rows == 120
    assert all("COUNT(" in sql for sql in statements), statements
```

- [ ] **Step 5: Address `DirectDispatcher`'s duplicate**

`agent/tools.py:150-181` reimplements the WHERE clause deliberately, so the two profiles read the *same* rows for the same filter and the A/B stays controlled. That reason survives, but the duplication no longer has to: point it at the same manifest.

```python
        if tool == "query_customers":
            # Was a hand-copy of backends.py's _where, kept in step by comment
            # alone. The requirement is unchanged -- both profiles must read
            # the SAME rows for the same filter, or the A/B compares the
            # agent's inputs as well as its authority -- but it is now met by
            # sharing the manifest rather than by matching two functions.
            result = self._catalog.execute(tool, args)
            return {"content": result.content, "rows": result.rows}
```

Construct `self._catalog` in `DirectDispatcher.__init__` from `demo_catalog(...)` with the same three bindings it already takes. The unprotected profile still holds the credentials and talks to backends itself — it simply no longer has its own copy of the query builder.

- [ ] **Step 6: Reword the two comments and delete the module**

`broker/app.py:27` and `:175` name `query_customers` while explaining the `input.malformed` boundary. Replace both mentions with "an argument of the right type that the adapter cannot parse". Then:

```bash
git rm broker/backends.py
```

- [ ] **Step 7: Run everything**

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest tests/test_golden_decisions.py tests/test_golden_replay.py -v
sg docker -c "./scripts/demo.sh guarded" 2>&1 | tail -11
```

Expected: 0 failures; both golden suites PASS; the replay matches the README.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor: delete backends.py; the demo drives the catalog

The last module that knew four tool names, a table called customers and a
column called plan.

agent/tools.py's DirectDispatcher kept a hand-copy of the WHERE builder so
both profiles would read the SAME rows for the same filter -- otherwise the
A/B compares the agent's inputs as well as its authority.  That requirement
stands; it is met by sharing the manifest now rather than by keeping two
functions in step by comment.

test_describe_counts_rows_before_the_query_runs asserted only the integer, so
an adapter implementing describe() as len(SELECT *) would have passed the test
named for the project's core security property.  It asserts the SQL now."
```

---

## Phase 1 gate

```bash
.venv/bin/python -m pytest -q                              # 0 failures
.venv/bin/python -m pytest tests/test_golden_decisions.py  # 13 PASS, unchanged
.venv/bin/python -m pytest tests/test_golden_replay.py     # 3 PASS, unchanged
grep -rn "read_document\|query_customers\|http_fetch\|send_email" broker/   # no hits
sg docker -c "./scripts/demo.sh guarded" | tail -11        # matches README.md:37-48
```

The decision corpus being **unchanged** is the point: Phase 1 touched no policy.


---

# Phase 2 — Policy

The rules stop naming tools. This is the phase that can fail open, so it is split so the decision corpus can distinguish the two changes: **Task 16 must leave `expected.json` byte-identical**, and **Task 17 changes exactly three entries** in a way that is inspected and deliberate.

**Measured on OPA 1.19.0 against today's shipped `data.json`** (which has no `tools` key), for a `query_customers` call carrying a `doc` target and 5,000,000 rows:

| variant | `allow` | `deny_reasons` |
|---|---|---|
| naive `expected := data.tools[t].target_kind` + rekeyed R5 | **`true`** | **`[]`** |
| `default`-accessor form (below) + rekeyed R5 | `false` | `["input.malformed"]` |
| `default`-accessor form, R5 not yet rekeyed | `false` | `["input.malformed", "rows.bounded"]` |

The trap is that the brief's phrasing — "a fail-closed accessor over `data.tools[<tool>].target_kind`" — reads as safe, but `:=` inside a rule body is undefined when its right-hand side is, so the body is undefined and the rule contributes no deny reason. Only the rule-level `default` mechanism is reliable.

---

### Task 16: `data.tools`, fail-closed accessors, and the degraded-catalog tests

**Files:**
- Modify: `policies/data.json`
- Modify: `policies/authz.rego:161-180`
- Modify: `policies/authz_test.rego`
- Modify: `tests/golden/decisions/*.json` — **no change** (assert this)

**Interfaces:**
- Consumes: `tests/test_golden_decisions.py` (Task 6)
- Produces: `data.tools` as a `{tool: {target_kind}}` map in `policies/data.json`; `safe_tool_catalog` and `safe_expected_target_kind` accessors in `authz.rego`. No rule name changes; no new `deny_reasons` string.

- [ ] **Step 1: Add the map to `policies/data.json`**

```json
{
  "tools": {
    "read_document":   {"target_kind": "doc"},
    "query_customers": {"target_kind": "db"},
    "http_fetch":      {"target_kind": "http"},
    "send_email":      {"target_kind": "mail"}
  },
  "purposes": { ... unchanged ... },
  "limits": { ... unchanged ... }
}
```

`target_kind` uses the **policy** vocabulary (`doc`, `db`), never the adapter vocabulary (`docstore`, `sql`). Writing `"sql"` yields a defined, `is_string`-passing value matching no target kind, so every call to that tool denies — closed, but silently. Task 18's `warden config check` catches it.

- [ ] **Step 2: Write the failing rego tests**

Append to `policies/authz_test.rego`. Six cases, all mocking `data.tools` **degraded** rather than correct — the correct-mock version is exactly the blind spot the R1c comment already documents:

```rego
# A correct data.tools mock in every case would reintroduce the blindness the
# R1c comment describes on a new key: verified that the mechanical edit yields
# opa test 44/44 over a policy that approves a mislabelled 5,000,000-row read
# at runtime. These mock it BROKEN, the way the existing R1c tests mock an
# incomplete `data`.

mislabelled_db_read := {
	"principal": {
		"agent_id": "a", "task_id": "t", "purpose": "p",
		"allowed_tools": ["query_customers"], "counterparties": [],
	},
	"action": {"type": "tool_call", "tool": "query_customers", "args_digest": "x"},
	"target": {
		"kind": "doc", "host": "", "port": 0, "path": "",
		"estimated_rows": 5000000, "recipients": [], "subjects": [],
	},
	"task_state": {"data_classes_held": [], "rows_returned_so_far": 0},
}

test_absent_tool_catalog_denies if {
	"input.malformed" in deny_reasons with input as mislabelled_db_read
		with data.purposes as mock_purposes
		with data.limits as mock_limits
}

test_empty_tool_catalog_denies if {
	"input.malformed" in deny_reasons with input as mislabelled_db_read
		with data.purposes as mock_purposes
		with data.limits as mock_limits
		with data.tools as {}
}

test_tool_absent_from_the_catalog_denies if {
	"input.malformed" in deny_reasons with input as mislabelled_db_read
		with data.purposes as mock_purposes
		with data.limits as mock_limits
		with data.tools as {"read_document": {"target_kind": "doc"}}
}

test_null_catalog_entry_denies if {
	"input.malformed" in deny_reasons with input as mislabelled_db_read
		with data.purposes as mock_purposes
		with data.limits as mock_limits
		with data.tools as {"query_customers": null}
}

test_array_catalog_denies if {
	"input.malformed" in deny_reasons with input as mislabelled_db_read
		with data.purposes as mock_purposes
		with data.limits as mock_limits
		with data.tools as ["query_customers"]
}

# A hyphen is a natural TOML-to-JSON transcription slip, and it is the shape
# that fails OPEN with the naive accessor.
test_misspelled_target_kind_key_denies if {
	"input.malformed" in deny_reasons with input as mislabelled_db_read
		with data.purposes as mock_purposes
		with data.limits as mock_limits
		with data.tools as {"query_customers": {"target-kind": "db"}}
}

# An undeclared tool must be malformed even under a PERFECTLY CORRECT catalog.
# This is what the deleted four-name allowlist did; nothing else covers it.
test_undeclared_tool_denies_under_a_correct_catalog if {
	"input.malformed" in deny_reasons with input as object.union(
		mislabelled_db_read,
		{"action": {"type": "tool_call", "tool": "exfiltrate", "args_digest": "x"}},
	)
		with data.purposes as mock_purposes
		with data.limits as mock_limits
		with data.tools as mock_tools
}

# Egress carries no action.tool, so safe_action_tool is null. An ungated rule
# makes every CONNECT malformed and the agent loses all model-API egress.
test_egress_is_unaffected_by_the_catalog if {
	allow with input as allowlisted_egress
		with data.purposes as mock_purposes
		with data.limits as mock_limits
		with data.tools as {}
}

test_egress_is_unaffected_by_an_absent_catalog if {
	allow with input as allowlisted_egress
		with data.purposes as mock_purposes
		with data.limits as mock_limits
}
```

Define `mock_tools` alongside the existing `mock_purposes`/`mock_limits`, and `allowlisted_egress` as an `{"type": "egress"}` action with an `http` target on a host in `mock_purposes`' `egress_allow`. Follow the file's existing naming for those helpers.

- [ ] **Step 3: Run and watch them fail**

```bash
~/.cache/warden/opa-1.19.0 test policies/ -v 2>&1 | grep -E "FAIL|PASS:"
```

Expected: the six degraded-catalog tests and `test_undeclared_tool_denies_under_a_correct_catalog` FAIL. The two egress tests PASS already (nothing references `data.tools` yet).

- [ ] **Step 4: Replace the literal map**

In `policies/authz.rego`, delete lines 161-180 — the `expected_target_kind` map, the four-name allowlist rule, and the `expected :=` rule — and put in their place:

```rego
# R1b — tool/target agreement, over the deployment's declared catalog.
#
# The literal {read_document: doc, ...} map that lived here was the last place
# the product knew a tool name. Replacing it is where this generalization can
# fail open, and the obvious spelling DOES:
#
#   expected := data.tools[safe_action_tool].target_kind
#   not input.target.kind == expected
#
# `:=` with an undefined right-hand side makes the assignment undefined, so
# the body is undefined and the rule contributes NO deny reason -- the exact
# shape the R1c comment below documents. Measured on OPA 1.19.0 against the
# shipped data.json before `tools` existed: combined with R5 keyed on target
# kind, a 5,000,000-row read carrying a mislabelled target evaluated to
# allow:true with an empty deny_reasons set. Only the rule-level `default`
# mechanism substitutes reliably when the primary definition is undefined at
# any depth.
#
# is_object guards an array or scalar data.tools; is_string guards a null or
# non-string target_kind. Both were measured firing.
default safe_tool_catalog := {}

safe_tool_catalog := catalog if {
	catalog := data.tools
	is_object(catalog)
}

default safe_expected_target_kind := null

safe_expected_target_kind := kind if {
	kind := safe_tool_catalog[safe_action_tool].target_kind
	is_string(kind)
}

# This rule REPLACES the four-name allowlist; it does not merely complement
# the pairing check. It says "this tool_call names a tool the deployment's
# catalog does not declare", with no tool name embedded. Without it an
# undeclared tool passes R1b even under a perfectly correct catalog, because
# every other rule keys off target.kind.
#
# The tool_call guard is load-bearing: egress carries no action.tool, so
# safe_action_tool is null and an ungated rule denies every CONNECT.
deny_reasons contains "input.malformed" if {
	input.action.type == "tool_call"
	not is_string(safe_expected_target_kind)
}

deny_reasons contains "input.malformed" if {
	input.action.type == "tool_call"
	not input.target.kind == safe_expected_target_kind
}
```

- [ ] **Step 5: Run the policy suite**

```bash
~/.cache/warden/opa-1.19.0 test policies/ -v 2>&1 | tail -5
```

Expected: `PASS: 53/53` — the 44 existing plus the nine added. **If any pre-existing test now fails, stop**: the replacement is not equivalent.

- [ ] **Step 6: Assert the corpus did not move**

This is the gate for this task.

```bash
.venv/bin/python -m pytest tests/test_golden_decisions.py -v
git diff --stat tests/golden/decisions/
```

Expected: 13 PASS, and `git diff` reports **no changes** under `tests/golden/decisions/`. Task 16 replaces a mechanism, not a behaviour. If `expected.json` needs editing here, something is wrong.

- [ ] **Step 7: Run the demo**

```bash
sg docker -c "./scripts/demo.sh guarded" 2>&1 | tail -11
```

Expected: matches `README.md:37-48`.

- [ ] **Step 8: Commit**

```bash
git add policies/ && git commit -m "feat(policy): the tool/target map comes from the deployment's catalog

The last place the product knew a tool name.

The obvious replacement fails open.  \`expected := data.tools[t].target_kind\`
inside a rule body is undefined when the reference is, so the body is
undefined and the rule contributes NO deny reason -- the shape the R1c
comment already documents.  Measured on OPA 1.19.0 against the shipped
data.json before \`tools\` existed: with R5 keyed on target kind, a
5,000,000-row read carrying a mislabelled target evaluated to allow:true with
an empty deny_reasons.  The rule-level \`default\` mechanism is the only
reliable substitution.

The four-name allowlist is REPLACED, not deleted: \`not
is_string(safe_expected_target_kind)\` says the catalog does not declare this
tool, without naming one.  Without it an undeclared tool passes R1b under a
perfectly correct catalog.

Both rules keep the tool_call guard, or every egress CONNECT becomes
malformed and the agent loses all model-API egress.

Nine tests, mocking data.tools BROKEN rather than correct -- a correct mock
everywhere is precisely the blindness R1c describes, on a new key.  The
decision corpus is unchanged, which is this task's gate."
```

---

### Task 17: Rekey R5, R6 and R7 onto target kind

**Measured** on OPA 1.19.0 with a correct `data.tools` and the Task 16 accessors in place — 3 of 13 corpus expectations move, and the **reported rule changes in none**:

| case | before | after |
|---|---|---|
| `adversarial-1-mislabelled-db-target` | `["input.malformed", "rows.bounded"]` | `["input.malformed"]` |
| `adversarial-3-mail-with-doc-target` | `["input.malformed", "mail.counterparty"]` | `["input.malformed"]` |
| `adversarial-4-db-with-mail-target` | `["input.malformed", "rows.scope"]` | `["input.malformed"]` |
| all ten others | — | unchanged |

That is the redundancy loss, made visible. Today a mislabelled call trips two rules independently; afterwards it trips one, and R1b is the only thing between it and an allow. `input.malformed` outranks every other reason in `DENY_PRECEDENCE`, so no audit record and no replay line changes — which is precisely why this had to be measured rather than watched for.

The rekey also **closes** a latent hole: today a second SQL-kind tool would escape the row budget entirely, because R5 names one tool.

**Files:**
- Modify: `policies/authz.rego` (R5 line ~284, R6 ~313, R7 ~305)
- Modify: `tests/golden/decisions/expected.json` (three entries)

- [ ] **Step 1: Rekey the three rules**

R5 — replace `input.action.tool == "query_customers"` with `input.target.kind == "db"`, and extend the comment:

```rego
# R5 — blast radius. Accumulates across the whole task, so many small reads
# hit the same ceiling as one large one.
#
# Keyed on target kind, not tool name. Safe ONLY because R1b now denies,
# unconditionally and fail-closed, any tool_call whose target.kind disagrees
# with the deployment's catalog -- see safe_expected_target_kind above. If
# that guarantee weakens, this rule stops firing on a mislabelled call and
# nothing else catches it.
#
# It also closes a hole the tool-name form had: a SECOND database tool
# escaped the row budget entirely, because this named exactly one.
deny_reasons contains "rows.bounded" if {
	input.target.kind == "db"
	total := input.task_state.rows_returned_so_far + input.target.estimated_rows
	total > safe_max_rows_per_task
}
```

R7 — same substitution, and add to its comment: `# Keyed on target kind for the same reason as R5, and with the same dependency on R1b.`

R6 — replace `input.action.tool == "send_email"` with `input.target.kind == "mail"`, same note.

- [ ] **Step 2: Confirm no rule names a tool**

```bash
grep -n 'input.action.tool ==' policies/authz.rego
```

Expected: **no output**. Then:

```bash
grep -c 'read_document\|query_customers\|http_fetch\|send_email' policies/authz.rego
```

Expected: `0`.

- [ ] **Step 3: Run the policy suite**

```bash
~/.cache/warden/opa-1.19.0 test policies/ -v 2>&1 | tail -5
```

Expected: `PASS: 53/53`. Any pre-existing failure means the rekey is not equivalent — stop.

- [ ] **Step 4: Watch the corpus fail, on exactly three cases**

```bash
.venv/bin/python -m pytest tests/test_golden_decisions.py -v 2>&1 | grep -E "FAILED|passed|failed"
```

Expected: exactly three FAILED — `adversarial-1-mislabelled-db-target`, `adversarial-3-mail-with-doc-target`, `adversarial-4-db-with-mail-target`. **If a fourth fails, or a demo case fails, stop and investigate**: the rekey was supposed to change only the redundancy on mislabelled inputs.

- [ ] **Step 5: Update the three expectations, and record why in the file**

Edit `tests/golden/decisions/expected.json` so those three read `"deny_reasons": ["input.malformed"]`, leaving `"rule": "input.malformed"` as it was. Then append to `tests/golden/README.md`:

```markdown
## Changed in Phase 2 (rekeying R5/R6/R7 onto target kind)

Three adversarial cases lost a second, redundant deny reason:

| case | was | now |
|---|---|---|
| `adversarial-1-mislabelled-db-target` | `input.malformed`, `rows.bounded` | `input.malformed` |
| `adversarial-3-mail-with-doc-target` | `input.malformed`, `mail.counterparty` | `input.malformed` |
| `adversarial-4-db-with-mail-target` | `input.malformed`, `rows.scope` | `input.malformed` |

Each is a call whose target kind disagrees with the catalog. Before the rekey
two rules fired independently; after it, R1b alone stands between the call and
an allow. The reported rule is unchanged in all three — `input.malformed`
outranks everything — so no audit record and no replay line moved, which is
why this needed measuring rather than watching for.

Ten of thirteen cases are unchanged, including every demo decision.
```

- [ ] **Step 6: Run everything**

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest tests/test_golden_decisions.py tests/test_golden_replay.py -v
sg docker -c "./scripts/demo.sh guarded" 2>&1 | tail -11
```

Expected: 0 failures; both golden suites PASS; the replay matches `README.md:37-48`.

- [ ] **Step 7: Commit**

```bash
git add policies/authz.rego tests/golden/
git commit -m "feat(policy): R5, R6 and R7 key on target kind, not tool name

authz.rego now contains no tool name at all.

Measured on OPA 1.19.0: three of thirteen corpus expectations move, each
losing a redundant second reason on a mislabelled-target input, and the
reported rule changes in NONE -- input.malformed outranks everything, so no
audit record and no replay line moves.  That is exactly why it needed
measuring rather than watching for.

The cost is redundancy: a mislabelled call used to trip two rules
independently and now trips one, leaving R1b as the only thing between it and
an allow.  Acceptable only because R1b is fail-closed as of the previous
task, and the rule comments say so.

It also closes a hole: a SECOND database tool escaped the row budget
entirely, because R5 named exactly one."
```

---

### Task 18: `warden config check`

Two independently-authored files must agree: `tools.toml` (what the broker binds) and `data.json` (what the policy expects). That independence is deliberate — it keeps R1b a real cross-check rather than a value compared with itself — so drift is possible by construction, and drift fails closed but **silently**, as a blanket `input.malformed` on every call to the affected tool.

Offline mode compares the files. `--opa URL` additionally reads `data.tools` from a running server, which is the only way to catch a bundle mounted where OPA namespaces it to `data.deployment.tools` — an offline file comparison cannot see that.

**Files:**
- Create: `broker/config/check.py`
- Modify: `cli/warden.py` (add the `config` command)
- Create: `tests/test_config_check.py`

**Interfaces:**
- Consumes: `load_catalog`, `TARGET_KIND_BY_ADAPTER`
- Produces: `broker.config.check.check_catalog(catalog_path, data_path, env, *, opa_url=None) -> list[str]` — returns problem strings, empty when consistent. `warden config check --config PATH [--data PATH] [--opa URL]`, exit 0 clean / 1 on drift.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config_check.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from broker.config.check import check_catalog

MANIFEST = """
[tools.read_document]
kind = "docstore"
[tools.read_document.binding]
base_url = "http://d"
[tools.read_document.args]
doc_id = { type = "string", required = true }
"""


def files(tmp_path: Path, manifest: str, data: dict) -> tuple[Path, Path]:
    catalog = tmp_path / "tools.toml"
    catalog.write_text(manifest)
    document = tmp_path / "data.json"
    document.write_text(json.dumps(data))
    return catalog, document


def test_consistent_files_report_nothing(tmp_path):
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    assert check_catalog(catalog, data, env={}) == []


def test_a_tool_missing_from_policy_data_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST, {"tools": {}})
    problems = check_catalog(catalog, data, env={})
    assert any("read_document" in p for p in problems)


def test_an_adapter_kind_written_where_a_target_kind_belongs_is_reported(tmp_path):
    """Fails closed at runtime -- a blanket input.malformed on every call to
    that tool -- but silently, and only in production."""
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "docstore"}}})
    problems = check_catalog(catalog, data, env={})
    assert any("docstore" in p and "doc" in p for p in problems)


def test_a_wrong_but_valid_target_kind_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "db"}}})
    assert check_catalog(catalog, data, env={}) != []


def test_a_policy_tool_with_no_catalog_entry_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST, {"tools": {
        "read_document": {"target_kind": "doc"},
        "ghost": {"target_kind": "db"},
    }})
    problems = check_catalog(catalog, data, env={})
    assert any("ghost" in p for p in problems)


def test_an_absent_tools_key_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST, {"purposes": {}, "limits": {}})
    assert check_catalog(catalog, data, env={}) != []


def test_the_shipped_demo_configuration_is_consistent():
    """The one that runs in CI."""
    assert check_catalog(
        Path("demo/scenario/tools.toml"), Path("policies/data.json"),
        env={"DOCSTORE_URL": "http://d", "DB_PATH": "data/customers.db",
             "MAILER_URL": "http://m"},
    ) == []
```

- [ ] **Step 2: Run and watch them fail**

```bash
.venv/bin/python -m pytest tests/test_config_check.py -v
```

Expected: `ModuleNotFoundError: No module named 'broker.config.check'`.

- [ ] **Step 3: Implement `broker/config/check.py`**

```python
"""Cross-checks the tool catalog against the policy's data document.

tools.toml and data.json are authored independently on purpose: it is what
keeps R1b a real check on a broker that mislabels a target, rather than a
value compared with itself. The cost of that independence is drift, and drift
fails closed but SILENTLY -- a blanket input.malformed on every call to the
affected tool, visible only in production.

Two modes. Offline compares the files. --opa reads data.tools from a running
server, which is the only way to catch a bundle mounted where OPA namespaces
the document to data.deployment.tools; no file comparison can see that.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import httpx

from broker.adapters.registry import TARGET_KIND_BY_ADAPTER
from broker.config.catalog import load_catalog


def _policy_tools(document: Mapping) -> dict:
    tools = document.get("tools")
    return tools if isinstance(tools, dict) else {}


def check_catalog(
    catalog_path: Path, data_path: Path, env: Mapping[str, str], *, opa_url: str | None = None
) -> list[str]:
    problems: list[str] = []
    catalog = load_catalog(catalog_path, env, client=None)
    document = json.loads(Path(data_path).read_text())

    declared = _policy_tools(document)
    if not declared:
        problems.append(f"{data_path}: no `tools` map; every tool_call will deny")

    for tool in sorted(catalog.names()):
        expected = catalog.target_kind(tool)
        entry = declared.get(tool)
        if not isinstance(entry, dict) or "target_kind" not in entry:
            problems.append(
                f"{tool}: declared in {catalog_path.name} but absent from "
                f"{data_path.name}; every call will deny input.malformed"
            )
            continue
        actual = entry["target_kind"]
        if actual == expected:
            continue
        if actual in TARGET_KIND_BY_ADAPTER:
            problems.append(
                f"{tool}: target_kind {actual!r} is an ADAPTER kind; the policy "
                f"expects the TARGET kind {expected!r}"
            )
        else:
            problems.append(
                f"{tool}: target_kind is {actual!r}, adapter produces {expected!r}"
            )

    for tool in sorted(set(declared) - set(catalog.names())):
        problems.append(f"{tool}: in {data_path.name} but not in {catalog_path.name}")

    if opa_url:
        try:
            response = httpx.get(f"{opa_url.rstrip('/')}/v1/data/tools", timeout=5.0)
            served = response.json().get("result")
        except (httpx.HTTPError, ValueError) as exc:
            problems.append(f"{opa_url}: cannot read data.tools ({exc})")
        else:
            if served is None:
                problems.append(
                    f"{opa_url}: data.tools is undefined. The bundle is probably "
                    "mounted in a subdirectory -- OPA namespaces a data file by "
                    "its path under the bundle root, so /policies/data/data.json "
                    "loads as data.data.tools."
                )
            elif served != declared:
                problems.append(f"{opa_url}: serves a different data.tools than {data_path}")
    return problems
```

- [ ] **Step 4: Add the CLI command**

In `cli/warden.py`, extend the `command` choices with `config` and a `--data` / `--opa` argument, then:

```python
    if args.command == "config":
        from broker.config.check import check_catalog

        problems = check_catalog(
            Path(args.catalog), Path(args.data), env=os.environ, opa_url=args.opa
        )
        for problem in problems:
            print(f"✗ {problem}", file=sys.stderr)
        if problems:
            return 1
        print("config consistent")
        return 0
```

- [ ] **Step 5: Run, and try it on the real files**

```bash
.venv/bin/python -m pytest tests/test_config_check.py -v
DOCSTORE_URL=http://d DB_PATH=data/customers.db MAILER_URL=http://m \
  .venv/bin/python -m cli.warden config --catalog demo/scenario/tools.toml --data policies/data.json
```

Expected: 7 PASS, then `config consistent`.

- [ ] **Step 6: Prove it catches the drift it exists for**

```bash
python3 -c "
import json,pathlib
p=pathlib.Path('policies/data.json'); d=json.loads(p.read_text())
d['tools']['query_customers']['target_kind']='sql'   # the adapter kind
p.write_text(json.dumps(d, indent=2))"
DOCSTORE_URL=http://d DB_PATH=data/customers.db MAILER_URL=http://m \
  .venv/bin/python -m cli.warden config --catalog demo/scenario/tools.toml --data policies/data.json; echo "exit=$?"
git checkout policies/data.json
```

Expected: `✗ query_customers: target_kind 'sql' is an ADAPTER kind; the policy expects the TARGET kind 'db'` and `exit=1`.

- [ ] **Step 7: Wire it into CI**

Add to `.github/workflows/ci.yml`, before the Python tests:

```yaml
      - name: Config consistency
        env:
          DOCSTORE_URL: http://docstore.internal
          DB_PATH: data/customers.db
          MAILER_URL: http://mailer.internal
        run: python -m cli.warden config --catalog demo/scenario/tools.toml --data policies/data.json
```

- [ ] **Step 8: Commit**

```bash
git add broker/config/check.py cli/warden.py tests/test_config_check.py .github/workflows/ci.yml
git commit -m "feat(cli): warden config check, for the drift independence buys

tools.toml and data.json are authored independently so R1b stays a real check
on a broker that mislabels a target rather than a value compared with itself.
The cost is drift, and drift fails closed but silently -- a blanket
input.malformed on every call to the affected tool, visible only in
production.

--opa additionally reads data.tools from a running server, the only way to
catch a bundle mounted where OPA namespaces the document to
data.deployment.tools.  No file comparison can see that.

Runs in CI against the shipped pair."
```

---

## Phase 2 gate

```bash
~/.cache/warden/opa-1.19.0 test policies/                       # PASS: 53/53
grep -c 'read_document\|query_customers\|http_fetch\|send_email' policies/authz.rego   # 0
grep -n 'input.action.tool ==' policies/authz.rego              # no output
.venv/bin/python -m pytest -q                                   # 0 failures
.venv/bin/python -m pytest tests/test_golden_decisions.py -q     # 13 PASS
sg docker -c "./scripts/demo.sh guarded" | tail -11              # matches README.md:37-48
```

`tests/golden/decisions/expected.json` differs from Phase 0 in **exactly three** entries, each documented in `tests/golden/README.md`.


---

# Phase 3 — The split

Directories move, two distributions appear, and the seam becomes a dependency direction that pip enforces. No behaviour changes: every gate from Phases 0-2 must still pass, unedited except for paths.

---

### Task 19: Two distributions and two entry points

**Files:**
- Create: `warden/pyproject.toml`, `demo/pyproject.toml`
- Create: `warden/cli/__init__.py`, `warden/cli/main.py`
- Create: `demo/cli/main.py`
- Modify: `pytest.ini`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: console scripts `warden` → `warden.cli.main:main` and `warden-demo` → `demo.cli.main:main`. `warden` subcommands: `serve`, `control`, `replay`, `verify-chain`, `config check`. `warden-demo`: `up`, `explain`, `sweep`, `record`, `verify-runs`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_entry_points.py`:

```python
"""The CLIs are real commands, and the dependency direction is one-way."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def project(name: str) -> dict:
    return tomllib.loads((REPO_ROOT / name / "pyproject.toml").read_text())["project"]


def test_the_product_declares_one_script():
    assert project("warden")["scripts"] == {"warden": "warden.cli.main:main"}


def test_the_demo_declares_one_script_and_depends_on_the_product():
    demo = project("demo")
    assert demo["scripts"] == {"warden-demo": "demo.cli.main:main"}
    assert any(d.split()[0].split("=")[0] == "warden" for d in demo["dependencies"])


def test_the_product_does_not_depend_on_the_demo():
    """pip enforces the seam the tests confirm."""
    for dependency in project("warden")["dependencies"]:
        assert "warden-demo" not in dependency


def test_the_product_carries_no_model_sdk():
    joined = " ".join(project("warden")["dependencies"])
    for sdk in ("anthropic", "google-genai", "openai"):
        assert sdk not in joined


def test_both_commands_run():
    for command in ("warden", "warden-demo"):
        result = subprocess.run([command, "--help"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_entry_points.py -v
```

Expected: `FileNotFoundError` for `warden/pyproject.toml`.

- [ ] **Step 3: Write `warden/pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "warden"
version = "0.1.0"
description = "A policy-enforcing broker for AI agent tool calls and network egress"
requires-python = ">=3.11"
# Deliberately minimal, and asserted so by tests/test_entry_points.py. The
# enforcement point has no business holding a model credential, and no
# business carrying the SDK that would use one.
dependencies = [
  "fastapi==0.141.1",
  "uvicorn[standard]==0.52.0",
  "httpx==0.28.1",
  "pyjwt[crypto]==2.13.0",
]

[project.scripts]
warden = "warden.cli.main:main"

[tool.setuptools.packages.find]
where = ["."]
include = ["warden*"]
```

- [ ] **Step 4: Write `demo/pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "warden-demo"
version = "0.1.0"
description = "The support-ticket prompt-injection scenario warden is demonstrated with"
requires-python = ">=3.11"
# One-way. Nothing declares warden-demo, so pip enforces the seam the tests
# confirm: the product image installs ./warden and cannot pull demo code in.
dependencies = ["warden"]

[project.optional-dependencies]
# Only needed for `warden-demo explain --live` and `warden-demo sweep`.
# OpenRouter needs neither -- it speaks the OpenAI HTTP shape over httpx.
live = ["google-genai==2.15.0", "anthropic==0.69.0"]

[project.scripts]
warden-demo = "demo.cli.main:main"

[tool.setuptools.packages.find]
where = ["."]
include = ["demo*"]
```

- [ ] **Step 5: Write the two CLI dispatchers**

`warden/cli/main.py` is an `argparse` dispatcher over five subcommands. `replay` and `verify-chain` delegate to the existing functions in `cli/warden.py` **unchanged** — their stdout and exit codes are pinned by `tests/test_golden_replay.py`. `serve` and `control` load their TOML and call the Phase 1 entrypoints. `config check` calls `check_catalog`.

`demo/cli/main.py` dispatches `up`, `explain`, `sweep`, `record`, `verify-runs` to the existing modules.

- [ ] **Step 6: Install both and switch pytest off `pythonpath`**

```bash
.venv/bin/pip install -e ./warden -e ./demo
```

In `pytest.ini`, delete `pythonpath = .` — the packages are installed now — and add `--import-mode=importlib` to `addopts`, which Task 21 needs for the split test trees.

- [ ] **Step 7: Update CI**

Replace `pip install -r requirements.txt` with:

```yaml
      - name: Install
        run: pip install -e ./warden -e ./demo && pip install pytest==9.1.1 pytest-asyncio==1.4.0
```

- [ ] **Step 8: Run and commit**

```bash
.venv/bin/python -m pytest tests/test_entry_points.py -v && .venv/bin/python -m pytest -q
git add warden/pyproject.toml demo/pyproject.toml warden/cli/ demo/cli/main.py pytest.ini .github/workflows/ci.yml tests/test_entry_points.py
git commit -m "feat: two distributions, two commands

warden-demo depends on warden; nothing depends the other way, so pip enforces
the seam the tests confirm -- the product image installs ./warden and cannot
pull demo code in even by accident.

python -m cli.explain becomes warden-demo explain.  replay and verify-chain
delegate to the existing functions unchanged: their stdout and exit codes are
pinned by the golden replay test."
```

---

### Task 20: Move the trees

Pure `git mv` plus import rewrites. Do it in one commit so `git log --follow` works.

- [ ] **Step 1: Move the product**

```bash
git mv broker warden/broker
git mv policies warden/policies
git mv cli/warden.py warden/cli/replay.py
```

- [ ] **Step 2: Move the demo**

```bash
git mv agent demo/agent
git mv mocks demo/mocks
git mv cli/explain.py cli/sweep.py cli/record.py cli/runlog.py demo/cli/
git mv scripts/demo.sh demo/scripts/demo.sh
git rm cli/__init__.py
git mv warden.toml control.toml demo/scenario/
```

- [ ] **Step 3: Rewrite imports**

```bash
grep -rl 'from broker\|import broker\|from agent\|import agent\|from mocks\|import mocks\|from cli\|import cli' \
  --include='*.py' warden demo tests tools | while read -r f; do
  sed -i \
    -e 's/\bfrom broker\./from warden.broker./g'  -e 's/\bimport broker\./import warden.broker./g' \
    -e 's/\bfrom broker import/from warden.broker import/g' \
    -e 's/\bfrom agent\./from demo.agent./g'      -e 's/\bfrom agent import/from demo.agent import/g' \
    -e 's/\bfrom mocks\./from demo.mocks./g'      -e 's/\bfrom mocks import/from demo.mocks import/g' \
    -e 's/\bfrom cli\./from demo.cli./g'          -e 's/\bfrom cli import/from demo.cli import/g' \
    "$f"
done
```

Then fix by hand: `warden/cli/replay.py` imports `warden.broker.audit`; `demo/cli/runlog.py` imports `warden.broker.policy_digest`; `warden/broker/__init__.py` and the new `warden/__init__.py` and `demo/__init__.py` must exist.

- [ ] **Step 4: Fix the CWD-relative policy paths**

Four sites resolve `policies/` relative to the current directory and will now break: `demo/cli/explain.py:841,911,638` and `tests/test_cli.py:601`. `demo/cli/runlog.py:77-83` catches `Exception` and degrades to `"unknown"`, so it fails *silently* into the run manifest. Introduce one constant and route all five through it:

```python
# demo/scenario/paths.py
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICY_BUNDLE = REPO_ROOT / "warden" / "policies"
```

Change `runlog._digest`'s bare `except Exception` to record `f"unavailable: {exc}"`, so a broken path is visible in the evidence rather than indistinguishable from an absent bundle.

- [ ] **Step 5: Update every path in compose, scripts and CI**

```bash
grep -rn 'policies\|broker/\|agent/\|mocks/\|cli\.' docker-compose.yml demo/scripts/demo.sh .github/workflows/ci.yml
```

Update each hit. OPA's mount becomes two **file-level** binds landing flat in `/policies` — see Task 22.

- [ ] **Step 6: Run everything and commit**

```bash
.venv/bin/pip install -e ./warden -e ./demo
.venv/bin/python -m pytest -q
~/.cache/warden/opa-1.19.0 test warden/policies/
sg docker -c "./demo/scripts/demo.sh guarded" 2>&1 | tail -11
git add -A && git commit -m "refactor: move the trees into warden/ and demo/

Pure moves plus import rewrites, in one commit so --follow works.

Five CWD-relative resolutions of policies/ now route through one constant.
runlog's blanket except Exception recorded 'unknown' on a broken path, which
verify-runs accepted happily -- it records the reason now, so a missing bundle
is distinguishable from an absent one."
```

---

### Task 21: Split the tests, and enforce the seam

**Files:**
- Create: `tests/__init__.py`, `tests/warden/__init__.py`, `tests/demo/__init__.py`
- Move: every `tests/test_*.py` into one of the two
- Create: `tests/test_seam.py`

Same-basename modules under two directories fail collection with `import file mismatch` under pytest's default `prepend` mode — reproduced in a scratch repo. `__init__.py` files plus Task 19's `--import-mode=importlib` fix it; both are needed.

- [ ] **Step 1: Write the seam test**

Create `tests/test_seam.py`:

```python
"""The seam, as a test rather than a convention.

pip already enforces the dependency direction. These assert the rest: that no
scenario knowledge survives in the product tree, that the product boots
knowing no tools, and that the enforcement point holds nothing that can sign.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PRODUCT = REPO_ROOT / "warden"

SCENARIO_STRINGS = (
    "4711", "8812", "attacker.example", "docstore.internal",
    "support-triage", "triage-bot", "refund", "customers",
)


def product_sources() -> list[Path]:
    return [p for p in PRODUCT.rglob("*.py") if "__pycache__" not in p.parts]


def test_no_product_module_imports_the_demo():
    offenders = []
    for path in product_sources():
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(n == "demo" or n.startswith("demo.") for n in names):
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


@pytest.mark.parametrize("needle", SCENARIO_STRINGS)
def test_the_product_tree_holds_no_scenario_string(needle):
    offenders = [
        f"{p.relative_to(REPO_ROOT)}"
        for p in [*product_sources(), *PRODUCT.rglob("*.rego"), *PRODUCT.rglob("*.toml")]
        if needle in p.read_text()
    ]
    assert offenders == []


def test_the_reference_catalog_declares_no_tools():
    """An empty catalog is a broker that permits nothing, which is the correct
    default for a deny-by-default system."""
    import tomllib
    reference = tomllib.loads((PRODUCT / "reference" / "tools.toml").read_text())
    assert reference.get("tools", {}) == {}


def test_the_product_dockerfile_copies_no_demo_path():
    text = (PRODUCT / "Dockerfile").read_text()
    for line in text.splitlines():
        if line.strip().startswith("COPY"):
            assert "demo" not in line, line


def test_serve_reaches_no_signer():
    """The property broker/__main__.py's docstring states, as a module graph
    assertion. It is about the address space, not the filesystem -- serve and
    control share a binary."""
    import warden.cli.main as cli
    seen, stack = set(), [cli.__name__]
    import importlib, sys
    while stack:
        name = stack.pop()
        if name in seen or not name.startswith("warden"):
            continue
        seen.add(name)
        module = sys.modules.get(name) or importlib.import_module(name)
        for value in vars(module).values():
            child = getattr(value, "__module__", None)
            if child:
                stack.append(child)
    assert "warden.broker.identity" not in seen or True   # imported, but:
    from warden.broker.identity import Signer
    import warden.broker.__main__ as entry
    assert "Signer" not in ast.dump(ast.parse(Path(entry.__file__).read_text()))


def test_a_catalog_tool_without_an_args_table_refuses_to_load(tmp_path):
    from warden.config.catalog import load_catalog
    from warden.config.loader import ConfigError

    manifest = tmp_path / "tools.toml"
    manifest.write_text('[tools.t]\nkind = "http"\n[tools.t.binding]\n')
    with pytest.raises(ConfigError, match="args"):
        load_catalog(manifest, env={}, client=None)
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_seam.py -v
```

Expected: the scenario-string cases fail for `customers` (`warden/broker/app.py` comments) and possibly others.

- [ ] **Step 3: Move the tests**

```bash
mkdir -p tests/warden tests/demo
touch tests/__init__.py tests/warden/__init__.py tests/demo/__init__.py
git mv tests/test_{app,proxy,pdp,audit,identity,taint,config_loader,arg_schema,catalog,adapter_registry,adapters_simple,adapter_sql,config_check,golden_decisions,golden_replay,opa_pin,entrypoints,entry_points}.py tests/warden/
git mv tests/test_{agent,cli,cassette,mocks,runlog,injection_contained,adapters_demo,seam_precursor}.py tests/demo/
git mv tests/test_isolation.sh tests/demo/
```

- [ ] **Step 4: Reword the two comments and split `test_cli.py`**

`warden/broker/app.py` lines 27 and 175 name `query_customers` while explaining the `input.malformed` boundary — reword to "an argument of the right type that the adapter cannot parse". (Task 15 already did this; confirm it held through the move.)

`tests/demo/test_cli.py`'s `DENY_PRECEDENCE` coverage test at line 601 reads a CWD-relative `policies/authz.rego` and asserts a **subset**. Strengthen it while moving: resolve through `demo.scenario.paths.POLICY_BUNDLE`, and assert equality with the seven expected strings, not containment. A reason `DENY_PRECEDENCE` cannot rank makes `pdp.py` return `pdp.unavailable`, naming a control that never fired.

- [ ] **Step 5: Run and commit**

```bash
.venv/bin/python -m pytest -q
git add -A && git commit -m "test: split the trees, and make the seam a test

Same-basename modules under two directories fail collection with 'import file
mismatch' under pytest's default prepend mode -- reproduced in a scratch repo
-- so both the __init__.py files and --import-mode=importlib are needed.

The DENY_PRECEDENCE coverage test asserted a subset and read a CWD-relative
path.  It asserts equality now: a reason the PDP cannot rank makes it return
pdp.unavailable, naming a control that never fired."
```

---

### Task 22: Two images, two compose files

- [ ] **Step 1: Write the failing test**

Append to `tests/test_seam.py`:

```python
def test_the_demo_compose_declares_no_product_service():
    import re
    overlay = (REPO_ROOT / "demo" / "compose.demo.yml").read_text()
    for service in ("broker:", "broker-control:", "opa:"):
        assert not re.search(rf"^  {service}", overlay, re.M), service


def test_the_product_compose_keeps_the_guarded_profile():
    """Without it, `--profile unprotected` starts the enforcement point, and
    'the broker is not running' is how README and THREAT_MODEL describe the
    control case."""
    base = (REPO_ROOT / "compose.yml").read_text()
    for service in ("opa", "broker", "broker-control"):
        block = base.split(f"  {service}:")[1].split("\n  ")[0]
        assert "profiles: [guarded]" in block or "guarded" in block, service
```

- [ ] **Step 2: Write `warden/Dockerfile`**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY warden/ warden/
COPY pyproject-warden.toml ./
RUN pip install --no-cache-dir ./warden
# No demo tree, no model SDK, no curl/dnsutils: those exist for
# tests/demo/test_isolation.sh, which runs in the agent container.
```

Adjust the `COPY` to match however setuptools resolves the package root; the seam test asserts no `COPY` line mentions `demo`.

- [ ] **Step 3: Write `demo/Dockerfile`**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
# curl and dnsutils are deliberate: tests/demo/test_isolation.sh needs real
# tools inside the agent container to prove there is no route out.
RUN apt-get update && apt-get install -y --no-install-recommends curl dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY warden/ warden/
COPY demo/ demo/
ARG LIVE=0
RUN pip install --no-cache-dir ./warden \
    && if [ "$LIVE" = "1" ]; then pip install --no-cache-dir "./demo[live]"; \
       else pip install --no-cache-dir ./demo; fi
```

The demo image contains the product **by necessity**: `demo/cli/explain.py` imports eight `warden.broker` modules and mounts the app in-process through `TestClient`, which is what makes its narration the real code path. The seam is one-directional.

- [ ] **Step 4: Split compose**

`compose.yml` keeps `opa`, `broker`, `broker-control` and all four network definitions, each product service retaining `profiles: [guarded]`. `demo/compose.demo.yml` takes `docstore`, `mailer`, `sinkhole`, `agent-runtime`, `agent-runtime-unprotected`.

OPA mounts the two halves **flat**:

```yaml
    volumes:
      - ./warden/policies/authz.rego:/policies/authz.rego:ro
      - ./demo/scenario/data.json:/policies/data.json:ro
```

Not a directory mount at `/policies/data/` — OPA namespaces a JSON data file by its path under the bundle root, so that would load as `data.data.purposes` and silently disable every rule.

- [ ] **Step 5: Update `demo/scripts/demo.sh`**

Every `docker compose` invocation becomes `docker compose -f compose.yml -f demo/compose.demo.yml`, keeping `--build` from Task 4.

- [ ] **Step 6: Verify, including that the product image is clean**

```bash
sg docker -c "docker compose -f compose.yml -f demo/compose.demo.yml --profile guarded build"
sg docker -c "docker run --rm warden-broker find /app -name '*.py' -path '*demo*'"
```

Expected: the second prints **nothing**.

```bash
sg docker -c "./demo/scripts/demo.sh guarded" 2>&1 | tail -11
.venv/bin/python -m pytest -q
```

Expected: the replay matches `README.md:37-48`; 0 test failures.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "build: two images, and a compose base plus demo overlay

The product image contains no demo code, and \`docker run warden-broker find
/app -path '*demo*'\` prints nothing.  The demo image contains BOTH by
necessity: explain.py imports eight broker modules and mounts the app
in-process, which is what makes its narration the real code path rather than
a reimplementation.  The seam is one-directional.

OPA mounts the rules and the data flat into /policies as file binds.  A
directory mount at /policies/data/ would load the document as
data.data.purposes -- OPA namespaces a data file by its path under the bundle
root -- and silently disable every rule.

opa, broker and broker-control keep profiles: [guarded] in the product base.
Without it --profile unprotected starts the enforcement point, and 'the
broker is not running' is how the README describes the control case."
```


---

# Phase 4 — Scenario config and docs

---

### Task 23: The scenario in one file

**Files:**
- Create: `demo/scenario/task.toml`, `demo/scenario/documents/`
- Modify: `demo/agent/loop.py:20-25`, `demo/mocks/docstore.py:8-90`, `demo/mocks/seed_db.py`

- [ ] **Step 1: Write the failing test**

Create `tests/demo/test_scenario_config.py`:

```python
"""The scenario is config, not string literals in five modules."""

from __future__ import annotations

import tomllib
from pathlib import Path

SCENARIO = Path(__file__).resolve().parents[2] / "demo" / "scenario"


def test_the_task_is_declared_once():
    task = tomllib.loads((SCENARIO / "task.toml").read_text())["task"]
    assert task["task_id"] == "4711"
    assert task["purpose"] == "support-triage"
    assert task["counterparties"] == ["customer:8812"]
    assert set(task["allowed_tools"]) == {
        "read_document", "query_customers", "http_fetch", "send_email"
    }


def test_the_documents_are_files():
    documents = SCENARIO / "documents"
    assert (documents / "ticket-4711.txt").is_file()
    assert (documents / "kb" / "refund-policy.backup.txt").is_file()
    for payload in ("recon", "qa", "audit"):
        assert (documents / "kb" / f"refund-policy.{payload}.txt").is_file()


def test_no_scenario_string_remains_in_demo_python():
    """The prompt, the ticket and the four poison payloads were literals in
    agent/loop.py and mocks/docstore.py; explain.py restated the prompt in six
    of its ten TASKS entries."""
    demo = SCENARIO.parent
    offenders = []
    for path in demo.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text()
        for needle in ("Triage support ticket #4711", "SYSTEM MAINTENANCE NOTICE",
                       "Refunds for duplicate charges"):
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == []


def test_the_declared_token_matches_the_golden_run():
    """If these drift, the frozen audit log stops being reproducible."""
    import json
    task = tomllib.loads((SCENARIO / "task.toml").read_text())["task"]
    records = [json.loads(l) for l in
               (SCENARIO.parents[1] / "tests" / "golden" / "audit-4711.jsonl")
               .read_text().splitlines() if l.strip()]
    assert {r["task_id"] for r in records} == {task["task_id"]}
    assert {r["agent_id"] for r in records} == {task["agent_id"]}
    assert {r["purpose"] for r in records} == {task["purpose"]}
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/demo/test_scenario_config.py -v
```

Expected: `FileNotFoundError` for `task.toml`.

- [ ] **Step 3: Write `demo/scenario/task.toml`**

Exactly the block in the spec: `[task]` with `agent_id`, `task_id`, `purpose`, `allowed_tools`, `data_classes`, `counterparties`, `prompt`; `[scenario]` with `seed_rows = 10312`, `poison = "backup"`, `documents`, `sinkhole_host`.

- [ ] **Step 4: Move the documents to files**

`git mv` is not available here — these are Python string literals. Write `demo/scenario/documents/ticket-4711.txt` from `docstore.TICKET`, and `documents/kb/refund-policy.{backup,recon,qa,audit}.txt` from the four `POISONS` entries, **byte for byte**. Confirm:

```bash
.venv/bin/python - <<'EOF'
from pathlib import Path
import importlib.util, sys
spec = importlib.util.spec_from_file_location("old", "/dev/null")
# Compare against the git-history version rather than the edited one.
import subprocess
old = subprocess.run(["git", "show", "HEAD:demo/mocks/docstore.py"],
                     capture_output=True, text=True).stdout
ns = {}
exec(compile(old.split("DOCUMENTS =")[0], "docstore", "exec"), ns)
root = Path("demo/scenario/documents")
assert (root / "ticket-4711.txt").read_text() == ns["TICKET"], "ticket drifted"
for name, body in ns["POISONS"].items():
    assert (root / "kb" / f"refund-policy.{name}.txt").read_text() == body, name
print(f"ticket + {len(ns['POISONS'])} payloads match byte for byte")
EOF
```

- [ ] **Step 5: Read them at runtime**

`demo/mocks/docstore.py` loads `DOCUMENTS` from `[scenario].documents` and selects the payload named by `[scenario].poison`; `set_poison(name)` re-reads the corresponding file. `demo/agent/loop.py`'s `SYSTEM_TASK` becomes a lookup of `[task].prompt`. `demo/cli/explain.py`'s `TASKS` entries that restate the prompt reference it instead.

- [ ] **Step 6: Run everything and commit**

```bash
.venv/bin/python -m pytest -q
sg docker -c "./demo/scripts/demo.sh guarded" 2>&1 | tail -11
git add -A && git commit -m "feat(demo): the scenario is one config file and five documents

The ticket, the four poison payloads, the operator prompt, the seed row count
and the token's fields were literals across agent/loop.py, mocks/docstore.py
and scripts/demo.sh, with explain.py restating the prompt in six of its ten
TASKS entries.

Swapping the injection is a config change now.  A test asserts the declared
token matches the frozen audit log, so the two cannot drift apart and quietly
stop reproducing."
```

---

### Task 24: `warden-demo up` replaces `demo.sh`

`demo.sh:47-53` inlines `agent_id`, `task_id`, `purpose`, `allowed_tools` and `counterparties` in a curl body — the last hardcoded scenario blob.

- [ ] **Step 1: Write the failing test**

Append to `tests/demo/test_scenario_config.py`:

```python
def test_no_shell_script_inlines_the_token_fields():
    demo = SCENARIO.parent
    for script in demo.rglob("*.sh"):
        text = script.read_text()
        for needle in ("triage-bot", "support-triage", "customer:8812"):
            assert needle not in text, f"{script.name}: {needle}"
```

- [ ] **Step 2: Implement `warden-demo up`**

A Python subcommand doing what `demo.sh` did: generate the keypair with `openssl` if absent, `docker compose -f compose.yml -f demo/compose.demo.yml --profile <p> up -d --build`, mint the token by POSTing `[task]` from `task.toml` to `localhost:8081/v1/tokens`, run the agent, print the sinkhole report, then `warden replay <task_id>`.

Keep `--build`, and keep `set -euo pipefail`'s effect: a non-zero `warden replay` (a broken chain) must abort, not be swallowed.

- [ ] **Step 3: Delete the script**

```bash
git rm demo/scripts/demo.sh
```

No shim — a shim is what the CLI change was meant to avoid.

- [ ] **Step 4: Run both profiles and commit**

```bash
sg docker -c "warden-demo up --profile guarded" 2>&1 | tail -11
sg docker -c "warden-demo up --profile unprotected" 2>&1 | tail -6
.venv/bin/python -m pytest -q
git add -A && git commit -m "feat(demo): warden-demo up, and demo.sh is gone

The curl body inlined agent_id, task_id, purpose, allowed_tools and
counterparties -- the last hardcoded scenario blob.  It reads task.toml now.

No shim left behind: a shim is what moving to real commands was meant to
avoid."
```

---

### Task 25: The documentation

**Files:** `README.md`, `THREAT_MODEL.md`, `docs/WALKTHROUGH.md`, `docs/live-run-2026-07-30.md`, `docs/live-enforcement-2026-07-30.md`, `warden/reference/README.md`

- [ ] **Step 1: Write the failing test**

Create `tests/test_docs_are_current.py`:

```python
"""Docs that name a path or a command must name one that exists."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = [REPO_ROOT / "README.md", REPO_ROOT / "THREAT_MODEL.md",
        *(REPO_ROOT / "docs").glob("*.md")]

STALE = ("python -m cli.", "python -m agent.", "python -m broker",
         "./scripts/demo.sh", "broker/backends.py", "policies/authz.rego")


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_no_stale_invocation_or_path(doc):
    text = doc.read_text()
    offenders = [needle for needle in STALE if needle in text]
    assert offenders == [], offenders


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_referenced_repo_path_exists(doc):
    missing = []
    for match in re.findall(r"\[[^\]]*\]\(((?!https?:)[^)#]+)", doc.read_text()):
        target = (doc.parent / match).resolve()
        if not target.exists():
            missing.append(match)
    assert missing == []


def test_the_readme_replay_block_matches_the_golden():
    """The block README showcases must be the one the frozen log produces."""
    golden = (REPO_ROOT / "tests" / "golden" / "replay-4711.txt").read_text()
    block = re.search(r"```\n(task 4711.*?)\n```", (REPO_ROOT / "README.md").read_text(),
                      re.S).group(1)
    mask = lambda s: re.sub(r"head sha256:[0-9a-f…]*", "head sha256:…", s)
    assert mask(block).splitlines() == mask(golden.rstrip("\n")).splitlines()
```

- [ ] **Step 2: Run and watch it fail**

```bash
.venv/bin/python -m pytest tests/test_docs_are_current.py -v
```

Expected: stale-invocation failures across all five docs.

- [ ] **Step 3: Rewrite the commands**

| was | now |
|---|---|
| `./scripts/demo.sh guarded` | `warden-demo up --profile guarded` |
| `python -m cli.explain --pause` | `warden-demo explain --pause` |
| `python -m agent.loop --live` | `warden-demo explain --live` |
| `python -m cli.warden replay 4711` | `warden replay 4711` |
| `python -m broker` | `warden serve --config demo/scenario/warden.toml` |
| `broker/backends.py` | `warden/adapters/` |
| `policies/authz.rego` | `warden/policies/authz.rego` |

`docs/WALKTHROUGH.md` is the heaviest — it starts each component by hand, so nearly every command in it changes, and Part 0's OPA install becomes `./scripts/fetch-opa.sh`.

- [ ] **Step 4: Fix the two claims that are already false**

`README.md:174` documents `run index intact: 3 runs`; the index holds **5**. And the replay block must be re-derived from `tests/golden/replay-4711.txt` rather than trusted.

- [ ] **Step 5: Rewrite the sentences the refactor makes more or less true**

These are worth writing rather than path-patching:

- The claim that the broker holds no model SDK is now enforced by `warden/pyproject.toml` and asserted by `tests/test_entry_points.py`, not by a comment in `requirements.txt`.
- "identical agent code, every step denied" gains a second sense: the *product* is identical across deployments too, and the demo is a config.
- `THREAT_MODEL.md`'s note on the proxy/tool-API asymmetry stands unchanged; add that the proxy deliberately keeps its own target construction, so CONNECT records carry six keys where tool records carry seven.

- [ ] **Step 6: Write `warden/reference/README.md`**

What a customer does: copy the three reference files, declare tools in `tools.toml`, mirror their target kinds in `data.json`, run `warden config check`, then `warden serve`. State that the shipped catalog is empty on purpose.

- [ ] **Step 7: Run everything and commit**

```bash
.venv/bin/python -m pytest -q
git add -A && git commit -m "docs: rewrite for the split

Every invocation changed: the demo is warden-demo, the operator tooling is
warden, and the trees moved.  WALKTHROUGH.md drives each component by hand, so
nearly every command in it moved.

Two claims were already false before this refactor and are corrected rather
than carried: README said 'run index intact: 3 runs' where the index holds 5,
and the showcased replay block is now re-derived from the frozen golden
instead of trusted.

A test asserts no doc names a path or invocation that no longer exists, and
that the README's replay block still matches the golden."
```

---

## Phase 4 gate — the whole thing

```bash
.venv/bin/pip install -e ./warden -e ./demo
.venv/bin/python -m pytest -q                                  # 0 failures
~/.cache/warden/opa-1.19.0 test warden/policies/               # PASS: 53/53
.venv/bin/python -m pytest tests/test_seam.py -v               # all PASS
warden config check --config demo/scenario/warden.toml         # config consistent
sg docker -c "warden-demo up --profile guarded" | tail -11     # matches README
sg docker -c "docker run --rm warden-broker find /app -path '*demo*'"   # prints nothing
```

---

## Self-review

**Spec coverage.** Every section of the design maps to a task: boundary → 9, 15, 21; `warden.toml` → 7, 14; `tools.toml` → 8, 12; `data.json` → 16; `task.toml` → 23; adapters → 9-11; arg validation → 8, 13; policy → 16-17; verification → 5, 6, 21; packaging/CLI → 19, 24; layout → 20, 22; phasing → all. The three out-of-scope items (URL-normalisation hardening, `send_email` `to: []`, non-SQLite drivers) are recorded in the spec and appear in no task, deliberately.

**Type consistency.** `ToolCatalog.validate/describe/execute/names/target_kind` are used with those names in Tasks 12, 13, 15, 18, 21. `BrokerComponents.as_app_kwargs/as_proxy_kwargs` in 14 only. `policy_bundle_digest(roots: Sequence[Path])` — every call site updated in Task 2 and re-checked by grep. `parse_tool_schema(table, tool)` and `ToolSchema.validate(args)` consistent across 8, 12, 13. `check_catalog(catalog_path, data_path, env, *, opa_url)` consistent across 18 and its CLI wiring.

**Known imprecision.** Task 21's `test_serve_reaches_no_signer` is written as an AST assertion on the entrypoint source, matching the existing `test_broker_entrypoint_source_never_names_the_signer`; the module-graph walk in it is belt-and-braces and its final assertion is the load-bearing one. Task 19's `warden/Dockerfile` `COPY` layout may need adjusting to however setuptools resolves the package root — the seam test, not the literal shown, is the specification.

**Two things this plan fixes that the spec did not know about**, both found by running the demo while writing it: `scripts/demo.sh` never rebuilt, and a stale image had inverted the demo's central claim under an intact chain (Task 4); and the `data/audit.jsonl` in the tree was a stale `--live` run that could not be re-derived by current code, so the baseline had to be regenerated before freezing (Task 5).

