"""The product: a policy-enforcing broker for AI agent tool calls and network egress.

Kept as a package (not a bare directory), mirroring demo/__init__.py, so that
warden/pyproject.toml's explicit [tool.setuptools] packages list can name it.

broker/ and policies/ (Task 20) live in here as warden/broker and
warden/policies -- the product wheel is self-contained: every import under
this package resolves without the demo/ tree present on disk at all.
"""
