"""Re-exports the demo's catalog builder for the test suite.

The definition lives in demo/scenario/catalog.py because cli/explain.py (demo
code, not test code) needs it too. Kept importable from here as well so
existing test call sites -- and the many more this task adds -- do not each
have to know that. Everything asserted about subjects, row counts and arg
shapes is asserted about demo/scenario/tools.toml itself, the file the demo
actually loads.
"""

from __future__ import annotations

from demo.scenario.catalog import MANIFEST, demo_catalog

__all__ = ["MANIFEST", "demo_catalog"]
