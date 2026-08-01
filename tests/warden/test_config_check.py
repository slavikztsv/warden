from __future__ import annotations

import json
from pathlib import Path

from warden.broker.config.check import check_catalog

MANIFEST = """
[tools.read_document]
kind = "docstore"
[tools.read_document.binding]
base_url = "http://d"
[tools.read_document.args]
doc_id = { type = "string", required = true }
"""


def files(tmp_path: Path, manifest: str, data: dict) -> tuple[Path, Path]:
    catalog = tmp_path / "tools.toml"
    catalog.write_text(manifest)
    document = tmp_path / "data.json"
    document.write_text(json.dumps(data))
    return catalog, document


def test_consistent_files_report_nothing(tmp_path):
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    assert check_catalog(catalog, data, env={}) == []


def test_a_tool_missing_from_policy_data_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST, {"tools": {}})
    problems = check_catalog(catalog, data, env={})
    assert any("read_document" in p for p in problems)


def test_an_adapter_kind_written_where_a_target_kind_belongs_is_reported(tmp_path):
    """Fails closed at runtime -- a blanket input.malformed on every call to
    that tool -- but silently, and only in production."""
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "docstore"}}})
    problems = check_catalog(catalog, data, env={})
    assert any("docstore" in p and "doc" in p for p in problems)


def test_a_wrong_but_valid_target_kind_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "db"}}})
    assert check_catalog(catalog, data, env={}) != []


def test_a_policy_tool_with_no_catalog_entry_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST, {"tools": {
        "read_document": {"target_kind": "doc"},
        "ghost": {"target_kind": "db"},
    }})
    problems = check_catalog(catalog, data, env={})
    assert any("ghost" in p for p in problems)


def test_an_absent_tools_key_is_reported(tmp_path):
    catalog, data = files(tmp_path, MANIFEST, {"purposes": {}, "limits": {}})
    assert check_catalog(catalog, data, env={}) != []


def test_the_shipped_demo_configuration_is_consistent():
    """The one that runs in CI."""
    assert check_catalog(
        Path("demo/scenario/tools.toml"), Path("warden/policies/data.json"),
        env={"DOCSTORE_URL": "http://d", "DB_PATH": "data/customers.db",
             "MAILER_URL": "http://m"},
    ) == []


# --- The Task 13 finding, carried forward -----------------------------------
#
# No check exists that every argument an adapter dereferences unconditionally
# (args[name], not args.get(name, ...)) is `required = true` in the schema.
# When it is not, describe() raises KeyError, and the broker's widened
# client-caused branch (broker/app.py) audits it as input.malformed -- i.e.
# it blames the AGENT for what is really a config-authoring defect. Each
# adapter class declares its own REQUIRED_ARGS (see broker/adapters/*.py),
# the way _check_mail_binding already polices the analogous
# recipients_arg-in-fields case for mail.

HTTP_MANIFEST = """
[tools.http_fetch]
kind = "http"
[tools.http_fetch.binding]
data_class = "public"
[tools.http_fetch.args]
url = { type = "string", required = false }
"""


def test_an_unconditionally_dereferenced_arg_marked_optional_is_reported(tmp_path):
    """HttpAdapter.describe() reads args[url] with no default. A call that
    omits url raises KeyError there, not a validation failure -- so the
    schema marking it optional is a config-authoring defect, and it must be
    reported rather than only discovered in production."""
    catalog, data = files(tmp_path, HTTP_MANIFEST,
                          {"tools": {"http_fetch": {"target_kind": "http"}}})
    problems = check_catalog(catalog, data, env={})
    assert any("http_fetch" in p and "url" in p and "required" in p for p in problems)


def test_an_unconditionally_dereferenced_arg_marked_required_is_not_reported(tmp_path):
    """Positive control: today's shipped manifest already marks url
    required, so this class of problem must not fire against it."""
    manifest = HTTP_MANIFEST.replace(
        "url = { type = \"string\", required = false }",
        "url = { type = \"string\", required = true }",
    )
    catalog, data = files(tmp_path, manifest,
                          {"tools": {"http_fetch": {"target_kind": "http"}}})
    problems = check_catalog(catalog, data, env={})
    assert not any("url" in p and "required" in p for p in problems)


def test_an_arg_only_ever_read_with_get_is_not_reported_when_optional(tmp_path):
    """Negative control: doc_id is read via args.get(...) in describe(), so
    marking it optional is not this defect and must not be reported as one."""
    manifest = MANIFEST.replace(
        "doc_id = { type = \"string\", required = true }",
        "doc_id = { type = \"string\", required = false }",
    )
    catalog, data = files(tmp_path, manifest,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    problems = check_catalog(catalog, data, env={})
    assert not any("doc_id" in p and "required" in p for p in problems)
