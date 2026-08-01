"""The one place that knows where the shipped policy bundle lives on disk.

Five call sites used to spell `Path("policies")` or `"policies"` themselves,
each one implicitly assuming the process's current working directory was the
repo root. That was already fragile before Task 20; after it, "policies/" is
no longer even the right name -- the bundle moved to warden/policies/ -- so
every one of those five would silently resolve to a directory that does not
exist (or, worse, one that happens to). Anchoring on REPO_ROOT instead of CWD
means the demo's own tools (explain, runlog) and the test suite agree with
each other and keep working regardless of where the process was launched
from.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICY_BUNDLE = REPO_ROOT / "warden" / "policies"
