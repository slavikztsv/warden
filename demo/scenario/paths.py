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

Task 22 splits the bundle across two directories: POLICY_BUNDLE (the rules,
authz.rego, shipped with the product) and POLICY_DATA (the deployment's
facts, data.json, shipped with the demo). Every caller that starts its own
local `opa run` process or computes a digest must pass BOTH -- an OPA
instance handed only POLICY_BUNDLE now finds no data.purposes/data.limits
and silently denies everything, the same failure the flat compose mount
(compose.yml, demo/compose.demo.yml) is built to avoid. Passing the two as
separate positional roots, rather than one shared directory, keeps the
top-level namespacing OPA gives a bundle root: a file named directly as its
own root document (not discovered by walking a parent directory) merges into
`data` unqualified, exactly like the flat `/policies/authz.rego` +
`/policies/data.json` container mount.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICY_BUNDLE = REPO_ROOT / "warden" / "policies"
POLICY_DATA = REPO_ROOT / "demo" / "scenario" / "data.json"
