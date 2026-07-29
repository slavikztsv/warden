"""Deterministic digest of the policy bundle.

Stamped into every audit record so a decision can be replayed against the
exact policy that produced it. Test files are excluded — they do not affect
any decision.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def policy_bundle_digest(policies_dir: Path) -> str:
    digest = hashlib.sha256()
    paths = sorted(
        path
        for path in Path(policies_dir).iterdir()
        if path.is_file() and not path.name.endswith("_test.rego")
    )
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"
