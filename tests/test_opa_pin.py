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
    # CI no longer hardcodes a download URL -- it delegates to
    # scripts/fetch-opa.sh, which reads OPA_VERSION itself, so the only
    # literal left in ci.yml is the fetch destination fetch-opa.sh writes to.
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "fetch-opa.sh" in ci
    assert f"opa-{OPA_VERSION}" in ci


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
