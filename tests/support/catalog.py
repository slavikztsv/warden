"""Builds a catalog from the SHIPPED demo manifest.

Deliberately not a fixture describing the same four tools independently: a
test-local copy would keep passing while the file the demo actually loads
drifted. Everything asserted about subjects, row counts and arg shapes is
asserted about demo/scenario/tools.toml itself.
"""

from __future__ import annotations

from pathlib import Path

from broker.config.catalog import ToolCatalog, load_catalog

MANIFEST = Path(__file__).resolve().parent.parent.parent / "demo" / "scenario" / "tools.toml"


def demo_catalog(*, docstore_url: str, db_path, mailer_url: str, client) -> ToolCatalog:
    return load_catalog(
        MANIFEST,
        env={
            "DOCSTORE_URL": docstore_url,
            "DB_PATH": str(db_path),
            "MAILER_URL": mailer_url,
        },
        client=client,
    )
