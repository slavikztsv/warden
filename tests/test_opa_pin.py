"""The pinned OPA version is one value, and every resolution honours it.

Three resolutions existed and only two were pinned; the unpinned pair --
cli/explain.py and the integration fixture -- ran 0.70.0 while the image and
CI ran 1.19.0. OPA 1.0 made Rego v1 the default and changed `opa test`
defaults, so a policy passing 44/44 locally was not evidence about what
ships.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tools.opa_version import OPA_VERSION, resolve_opa

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_compose_pins_the_same_version():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    assert f"openpolicyagent/opa:{OPA_VERSION}" in compose


def test_ci_never_restates_the_version_or_path():
    """ci.yml must not know OPA_VERSION at all.

    It runs ./scripts/fetch-opa.sh and then whatever binary that script
    resolved and published as $OPA_BIN -- it states neither a version number
    nor a binary path itself. That is the whole point of routing through
    fetch-opa.sh: a version bump touches one file, not two. The complementary
    guarantee -- that fetch-opa.sh's resolution actually tracks OPA_VERSION
    rather than hardcoding it -- is test_fetch_opa_derives_the_pinned_version
    below.
    """
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "fetch-opa.sh" in ci
    assert "OPA_BIN" in ci
    assert OPA_VERSION not in ci


def test_fetch_opa_derives_the_pinned_version():
    """fetch-opa.sh must compute its version from tools.opa_version.OPA_VERSION
    via a command substitution, not restate "1.19.0" as a literal.

    ci.yml no longer states a version anywhere (see the test above), so this
    script is the only place left that could silently drift from the pinned
    constant. This re-executes the exact substitution the script uses --
    not a reimplementation of it -- so it fails if the script stops deriving
    the version at all (no command substitution assigning VERSION) or stops
    deriving it from this module (the substitution text no longer names
    tools.opa_version / OPA_VERSION).
    """
    script = (REPO_ROOT / "scripts" / "fetch-opa.sh").read_text()
    match = re.search(r'VERSION="\$\((.+?)\)"', script)
    assert match, "fetch-opa.sh must set VERSION via a command substitution"
    substitution = match.group(1)
    assert "tools.opa_version" in substitution
    assert "OPA_VERSION" in substitution

    derived = subprocess.run(
        ["bash", "-c", substitution],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert derived == OPA_VERSION


def test_no_module_resolves_opa_off_bare_path():
    """shutil.which("opa") anywhere means an unpinned resolution came back."""
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or ".venv" in path.parts:
            continue
        if path.name in ("opa_version.py", "test_opa_pin.py"):
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
