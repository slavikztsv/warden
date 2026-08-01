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
