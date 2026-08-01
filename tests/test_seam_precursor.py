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
    here = Path(__file__).resolve()
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in REPO_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts and ".venv" not in path.parts
        # Excludes this file itself: test_backends_module_is_gone's
        # __import__("broker.backends") has to name the module in order to
        # prove it cannot be imported, which would otherwise flag this test
        # as its own offender.
        and path.resolve() != here
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
