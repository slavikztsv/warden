"""The product: a policy-enforcing broker for AI agent tool calls and network egress.

Kept as a package (not a bare directory), mirroring demo/__init__.py, so that
warden/pyproject.toml's [tool.setuptools.packages.find] can discover it.

Phase 3 (Task 20) moves broker/ and policies/ in here as warden/broker and
warden/policies. Until then this package holds only warden/cli/ -- the
dispatcher created in Task 19 still imports the top-level broker.* and cli.*
packages that live at the repo root.
"""
