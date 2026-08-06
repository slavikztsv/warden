from __future__ import annotations

import re
from pathlib import Path

import pytest

from demo.mocks.seed_db import seed_customers
from demo.scenario.task import SCENARIO
from warden.broker.adapters.base import UnknownTool
from warden.broker.config.catalog import ToolCatalog, load_catalog
from warden.broker.config.loader import ConfigError


@pytest.fixture(scope="module")
def seeded_db(tmp_path_factory):
    """A real sqlite file seeded with the scenario's own row count.

    `demo_catalog(db_path=...)` already lets the caller choose the database
    -- the shipped manifest itself is what must not be faked, not the data
    behind it. Seeding [scenario].seed_rows (currently 10312) rows once per
    module keeps the tests below from depending on `data/customers.db`
    existing on disk, which on a fresh checkout it does not: that file is
    gitignored and only ever created by `warden-demo up`'s seeding step.
    """
    path = tmp_path_factory.mktemp("catalog-db") / "customers.db"
    seed_customers(path, SCENARIO["seed_rows"])
    return path


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
    with pytest.raises(ConfigError, match=re.escape("DOCSTORE_URL")):
        load_catalog(write(tmp_path, MANIFEST), env={}, client=None)


def test_an_unknown_adapter_kind_is_a_startup_failure(tmp_path):
    text = MANIFEST.replace('kind = "docstore"', 'kind = "graphql"')
    with pytest.raises(ConfigError, match=re.escape("graphql")):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_a_tool_without_an_args_table_is_a_startup_failure(tmp_path):
    text = MANIFEST.split("[tools.read_document.args]")[0]
    with pytest.raises(ConfigError, match=re.escape("read_document")):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_a_missing_manifest_is_a_startup_failure(tmp_path):
    with pytest.raises(ConfigError, match=re.escape("tools.toml")):
        load_catalog(tmp_path / "tools.toml", env={}, client=None)


def test_the_shipped_demo_manifest_loads(seeded_db):
    """Not a fixture -- the real file, which is what every later assertion
    about subjects and row counts is made against."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path=seeded_db,
        mailer_url="http://mailer.internal",
        client=None,
    )
    assert catalog.names() == frozenset(
        {"read_document", "query_customers", "http_fetch", "send_email"}
    )
    assert catalog.target_kind("query_customers") == "db"
    assert catalog.target_kind("send_email") == "mail"


def test_data_class_reads_the_binding_not_the_result(seeded_db):
    """The spine charges a task's data class BEFORE execute() runs, so the
    class has to be knowable from config alone. It is: every adapter kind
    holds it as a binding property, which is why `warden config check` can
    already report a tool that declares none."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://d", db_path=seeded_db,
        mailer_url="http://m", client=None,
    )
    assert catalog.data_class("query_customers") == "pii"
    assert catalog.data_class("read_document") == "public"
    # send_email declares none, which is legitimate for a write -- see
    # cli/main.py's note. None must reach the store as "add nothing", not as
    # a class literally named "None".
    assert catalog.data_class("send_email") is None


def test_data_class_of_an_unknown_tool_raises(seeded_db):
    """Same failure as describe(), so the spine cannot get a silent None for
    a tool the catalog never heard of and charge it as classless."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://d", db_path=seeded_db,
        mailer_url="http://m", client=None,
    )
    with pytest.raises(UnknownTool):
        catalog.data_class("no_such_tool")


def test_the_shipped_manifest_reproduces_the_subject_join(seeded_db):
    """The prefix must join to the token's counterparties. Without its colon
    the ALLOWED read is denied rows.scope, the task never becomes tainted,
    and the egress to the allowlisted internal sink stops being refused."""
    from tests.support.catalog import demo_catalog

    catalog = demo_catalog(
        docstore_url="http://d", db_path=seeded_db,
        mailer_url="http://m", client=None,
    )
    assert catalog.describe("query_customers", {"filter": "id=8812"}).subjects == (
        "customer:8812",
    )
    assert catalog.describe("query_customers", {"filter": "all"}).subjects == ("*",)
    assert catalog.describe("query_customers", {"filter": "all"}).estimated_rows == (
        SCENARIO["seed_rows"]
    )


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
    with pytest.raises(ConfigError, match=re.escape("send_email")):
        load_catalog(write(tmp_path, text), env={"MAILER_URL": "http://m"}, client=None)


# --- Every [binding] key must be one the adapter kind actually reads -------
#
# Before the split, `data_class = "pii"` was compiled into broker/backends.py
# -- there was no key to misspell or drop. Moving it into config made it
# OMISSIBLE: an adapter's __init__ reads binding keys with dict.get(...), so
# an unrecognised key was silently IGNORED rather than rejected. This is the
# same shape of gap schema.py's `unknown_args` closes for [args]; catalog.py's
# _check_binding_keys closes it for [binding].


def test_a_misspelled_binding_key_is_a_startup_failure(tmp_path):
    """The reviewer's reproduction: `dataclass` (missing the underscore)
    where `data_class` belongs used to load cleanly and silently disable the
    PII data-flow control -- the tool's results would never taint the task."""
    text = MANIFEST.replace("data_class = \"public\"", "dataclass = \"public\"")
    with pytest.raises(ConfigError, match=re.escape("dataclass")):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_a_binding_key_that_belongs_to_a_different_adapter_kind_is_a_startup_failure(tmp_path):
    """`filter_arg` is a real key -- for SqlAdapter, not DocstoreAdapter. A
    key valid for one kind and typoed onto another must still fail, or a
    copy-pasted binding from one tool to another of a different kind loads
    cleanly and silently does nothing."""
    text = MANIFEST.replace(
        'data_class = "public"', 'data_class = "public"\nfilter_arg = "x"'
    )
    with pytest.raises(ConfigError, match=re.escape("filter_arg")):
        load_catalog(write(tmp_path, text), env={"DOCSTORE_URL": "x"}, client=None)


def test_the_shipped_demo_manifest_declares_only_recognised_binding_keys(seeded_db):
    """Positive control: the real manifest must keep loading cleanly under
    this check -- it is not exercised by test_the_shipped_demo_manifest_loads
    alone failing loudly if it broke, since that test does not assert
    anything binding-key-specific."""
    from tests.support.catalog import demo_catalog

    demo_catalog(
        docstore_url="http://docstore.internal", db_path=seeded_db,
        mailer_url="http://mailer.internal", client=None,
    )


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
    with pytest.raises(ConfigError, match=re.escape("send_email")):
        load_catalog(write(tmp_path, text), env={"MAILER_URL": "http://m"}, client=None)


def test_an_unknown_tool_table_key_is_refused(tmp_path):
    """A typo that silently disables a check is the failure the arg and
    binding allowlists exist to prevent. The tool table itself had none."""
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.lookup]\n'
        'kind = "docstore"\n'
        'descriptoin = "a typo"\n'
        '[tools.lookup.binding]\n'
        'base_url = "http://example.invalid"\n'
        '[tools.lookup.args]\n'
        'doc_id = { type = "string", required = true }\n'
    )
    with pytest.raises(ConfigError, match=re.escape("descriptoin")):
        load_catalog(manifest, env={}, client=None)


def test_description_and_title_reach_the_entry(tmp_path):
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.lookup]\n'
        'kind = "docstore"\n'
        'title = "Document lookup"\n'
        'description = "Fetch one document by id."\n'
        '[tools.lookup.binding]\n'
        'base_url = "http://example.invalid"\n'
        '[tools.lookup.args]\n'
        'doc_id = { type = "string", required = true }\n'
    )
    catalog = load_catalog(manifest, env={}, client=None)
    entry = catalog.entry("lookup")
    assert entry.title == "Document lookup"
    assert entry.description == "Fetch one document by id."


def test_a_non_string_description_is_refused(tmp_path):
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.lookup]\n'
        'kind = "docstore"\n'
        'description = 42\n'
        '[tools.lookup.binding]\n'
        'base_url = "http://example.invalid"\n'
        '[tools.lookup.args]\n'
        'doc_id = { type = "string", required = true }\n'
    )
    with pytest.raises(ConfigError, match=re.escape("description")):
        load_catalog(manifest, env={}, client=None)
