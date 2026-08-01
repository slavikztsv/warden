"""Builds a `ToolCatalog` from the SHIPPED demo manifest.

Lives here, not in tests/, because two non-test importers need it: the demo
runner (cli/explain.py) and the broker's own entrypoint (broker/__main__.py),
both of which run the real demo scenario. tests/support/catalog.py
re-exports these names rather than defining its own copy, so there is one
definition and the shipped manifest stays the only source -- a test-local
copy would keep passing while the file the demo actually loads drifted.
"""

from __future__ import annotations

from pathlib import Path

from warden.broker.config.catalog import ToolCatalog, load_catalog

MANIFEST = Path(__file__).resolve().parent / "tools.toml"


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
