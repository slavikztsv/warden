from __future__ import annotations

from pathlib import Path

import pytest

from broker.adapters.base import UnknownTool
from broker.config.catalog import ToolCatalog, load_catalog
from broker.config.loader import ConfigError

MANIFEST = """
[tools.read_document]
kind = "docstore"
[tools.read_document.binding]
base_url   = "${DOCSTORE_URL}"
data_class = "public"
[tools.read_document.args]
doc_id = { type = "string", required = true, non_empty = true }
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "tools.toml"
    path.write_text(text)
    return path


def test_an_empty_catalog_is_legal_and_knows_nothing():
    """The product ships no tools. An empty catalog is a broker that permits
    nothing, which is the correct default for a deny-by-default system."""
    catalog = ToolCatalog({})
    assert catalog.names() == frozenset()
    assert "read_document" not in catalog
    with pytest.raises(UnknownTool):
        catalog.describe("read_document", {})
    with pytest.raises(UnknownTool):
        catalog.execute("read_document", {})


def test_validate_defers_on_an_unknown_tool():
    """It must DEFER, not deny. Today an unrecognised tool passes the shape
    check, reaches describe(), raises UnknownTool and is audited under
    tools.allowed with target.kind "unknown". Denying here instead would
    change the audited rule to input.malformed and merge two different
    incidents into one reason."""
    assert ToolCatalog({}).validate("anything", {"x": 1}) is True


def test_loads_a_manifest_and_interpolates_bindings(tmp_path):
    catalog = load_catalog(
        write(tmp_path, MANIFEST),
        env={"DOCSTORE_URL": "http://docstore.internal"},
        client=None,
    )
    assert catalog.names() == frozenset({"read_document"})
    assert catalog.target_kind("read_document") == "doc"
    assert catalog.validate("read_document", {"doc_id": "x"}) is True
    assert catalog.validate("read_document", {"doc_id": ""}) is False
    assert catalog.validate("read_document", {"doc_id": "x", "junk": 1}) is False


def test_an_unset_binding_variable_is_a_startup_failure(tmp_path):
    with pytest.raises(ConfigError, match="DOCSTORE_URL"):
        load_catalog(write(tmp_path, MANIFEST), env={}, client=None)


def test_an_unknown_adapter_kind_is_a_startup_failure(tmp_path):
    text = MANIFEST.replace('kind = "docstore"', 'kind = "graphql"')
    with pytest.raises(ConfigError, match="graphql"):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_a_tool_without_an_args_table_is_a_startup_failure(tmp_path):
    text = MANIFEST.split("[tools.read_document.args]")[0]
    with pytest.raises(ConfigError, match="read_document"):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_a_missing_manifest_is_a_startup_failure(tmp_path):
    with pytest.raises(ConfigError, match="tools.toml"):
        load_catalog(tmp_path / "tools.toml", env={}, client=None)


def test_the_shipped_demo_manifest_loads(tmp_path):
    """Not a fixture -- the real file, which is what every later assertion
    about subjects and row counts is made against."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path="data/customers.db",
        mailer_url="http://mailer.internal",
        client=None,
    )
    assert catalog.names() == frozenset(
        {"read_document", "query_customers", "http_fetch", "send_email"}
    )
    assert catalog.target_kind("query_customers") == "db"
    assert catalog.target_kind("send_email") == "mail"


def test_the_shipped_manifest_reproduces_the_subject_join():
    """The prefix must join to the token's counterparties. Without its colon
    the ALLOWED read is denied rows.scope, the task never becomes tainted,
    and the egress to the allowlisted internal sink stops being refused."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://d", db_path="data/customers.db",
        mailer_url="http://m", client=None,
    )
    assert catalog.describe("query_customers", {"filter": "id=8812"}).subjects == (
        "customer:8812",
    )
    assert catalog.describe("query_customers", {"filter": "all"}).subjects == ("*",)
    assert catalog.describe("query_customers", {"filter": "all"}).estimated_rows == 10312


def test_a_mail_tool_whose_fields_omit_recipients_arg_is_a_startup_failure(tmp_path):
    """describe() reports recipients by reading args[recipients_arg]; execute()
    only forwards keys named in binding.fields. If recipients_arg is not itself
    one of those fields, describe() would audit a recipient set that execute()
    then silently drops from the wire -- the same audit-says-one-thing,
    action-does-another shape as the cc fail-open this closes for mail."""
    text = """
[tools.send_email]
kind = "mail"
[tools.send_email.binding]
base_url = "${MAILER_URL}"
fields = ["subject", "body"]
[tools.send_email.args]
to      = { type = "array", items = "string", required = true }
subject = { type = "string", required = true }
body    = { type = "string", required = true }
"""
    with pytest.raises(ConfigError, match="send_email"):
        load_catalog(write(tmp_path, text), env={"MAILER_URL": "http://m"}, client=None)


def test_a_mail_tool_with_an_explicit_recipients_arg_not_in_fields_is_a_startup_failure(tmp_path):
    text = """
[tools.send_email]
kind = "mail"
[tools.send_email.binding]
base_url = "${MAILER_URL}"
recipients_arg = "bcc"
fields = ["to", "subject", "body"]
[tools.send_email.args]
to      = { type = "array", items = "string", required = true }
subject = { type = "string", required = true }
body    = { type = "string", required = true }
"""
    with pytest.raises(ConfigError, match="send_email"):
        load_catalog(write(tmp_path, text), env={"MAILER_URL": "http://m"}, client=None)
