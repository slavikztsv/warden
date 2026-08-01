from __future__ import annotations

import json
from pathlib import Path

import httpx

from warden.broker.config.check import check_catalog, check_catalog_findings

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
        Path("demo/scenario/tools.toml"), Path("demo/scenario/data.json"),
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


def test_an_execute_time_unconditional_dereference_marked_optional_is_reported(tmp_path):
    """DocstoreAdapter.describe() reads args.get(doc_id, ""), so a check that
    only looked at describe() would wave this through -- but execute() reads
    args[doc_id] with no default. A manifest that leaves doc_id optional lets
    describe() (and the policy decision built on it) succeed on a call that
    then KeyErrors in execute() -- AFTER the allow is already durably
    audited, so the log asserts an authorised read that never happened. Must
    be reported."""
    manifest = MANIFEST.replace(
        "doc_id = { type = \"string\", required = true }",
        "doc_id = { type = \"string\", required = false }",
    )
    catalog, data = files(tmp_path, manifest,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    problems = check_catalog(catalog, data, env={})
    assert any("doc_id" in p and "required" in p for p in problems)


SQL_MANIFEST = """
[tools.query_rows]
kind = "sql"
[tools.query_rows.binding]
db = "rows.db"
table = "rows"
columns = ["id", "value"]
subject_column = "id"
default_column = "value"
[tools.query_rows.args]
filter = { type = "string", required = false }
"""


def test_a_get_based_optional_arg_is_not_reported_as_missing_required(tmp_path):
    """Negative control: SqlAdapter reads filter via args.get(...) in BOTH
    describe() and execute(), so marking it optional is not the
    unconditional-dereference defect and must not be reported as one."""
    catalog, data = files(tmp_path, SQL_MANIFEST,
                          {"tools": {"query_rows": {"target_kind": "db"}}})
    problems = check_catalog(catalog, data, env={})
    assert not any("filter" in p and "required" in p for p in problems)


# --- A binding value that names an argument, but not one the schema has ----
#
# REQUIRED_ARGS/EXECUTE_REQUIRED_ARGS above only catch a missing
# `required = true`. A DIFFERENT, worse defect survives even that: a binding
# key like filter_arg or arg naming an argument the [args] schema does not
# declare AT ALL. With the schema's default unknown_args = "reject", no valid
# call can ever populate a key the schema never mentions, so the adapter
# silently falls back to its own default on every single call.

BAD_DOC_ARG_MANIFEST = """
[tools.read_document]
kind = "docstore"
[tools.read_document.binding]
base_url = "http://d"
arg      = "id"
[tools.read_document.args]
doc_id = { type = "string", required = true }
"""


def test_a_docstore_binding_arg_absent_from_the_schema_is_reported(tmp_path):
    """binding.arg = "id" but the schema only declares doc_id. describe()
    then reads args.get("id", "") -- always "" -- so target.path is always
    empty, the policy has nothing to deny on, and execute() (which reads
    args["id"] unconditionally) raises KeyError AFTER that empty-path allow
    is durably audited. This is the exact defect the review reproduced."""
    catalog, data = files(tmp_path, BAD_DOC_ARG_MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    problems = check_catalog(catalog, data, env={})
    assert any("read_document" in p and "'id'" in p for p in problems)


BAD_FILTER_ARG_MANIFEST = """
[tools.query_rows]
kind = "sql"
[tools.query_rows.binding]
db         = "rows.db"
table      = "rows"
columns    = ["id", "value"]
subject_column = "id"
default_column = "value"
filter_arg = "flt"
[tools.query_rows.args]
filter = { type = "string", required = true }
"""


def test_a_sql_binding_filter_arg_absent_from_the_schema_is_reported(tmp_path):
    """binding.filter_arg = "flt" but the schema only declares filter. No
    valid call can ever populate "flt" (unknown_args defaults to reject), so
    describe()/execute() always see the "no filter" default -- every call to
    this tool becomes a silent, unbounded full-table read, no matter what
    the (never-consulted) `filter` argument requires."""
    catalog, data = files(tmp_path, BAD_FILTER_ARG_MANIFEST,
                          {"tools": {"query_rows": {"target_kind": "db"}}})
    problems = check_catalog(catalog, data, env={})
    assert any("query_rows" in p and "'flt'" in p for p in problems)


# --- warden config check reports a tool declaring no data_class ------------
#
# Advisory, not a hard failure: a write-only tool (send_email) legitimately
# has none. But on a tool whose result feeds back into the task, no
# data_class means that read can never taint the task, and a task that never
# taints cannot be stopped by the PII-sink rule (R7). Silently omitting it
# used to load cleanly and report "config consistent" -- see
# broker/config/catalog.py's _check_binding_keys, which catches the TYPO
# case (`dataclass`); this is the OMISSION case, which is not a typo and
# must not be a hard failure. MANIFEST (module-level, above) already
# declares no data_class -- that is the case under test here.

WITH_DATA_CLASS_MANIFEST = MANIFEST.replace(
    'base_url = "http://d"', 'base_url = "http://d"\ndata_class = "public"'
)


def test_a_reading_tool_with_no_data_class_is_a_finding(tmp_path):
    catalog = files(tmp_path, MANIFEST, {})[0]
    findings = check_catalog_findings(catalog, env={})
    assert any("read_document" in f and "data_class" in f for f in findings)


def test_a_reading_tool_with_no_data_class_is_not_a_hard_failure(tmp_path):
    """The exact reproduction from the review: deleting `data_class = "pii"`
    must not make `warden config check` merely say "config consistent" with
    nothing to see -- but it also must not fail the check outright, because
    the identical omission is correct for a write-only tool."""
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    assert check_catalog(catalog, data, env={}) == []


def test_a_tool_with_a_declared_data_class_is_not_a_finding(tmp_path):
    catalog = files(tmp_path, WITH_DATA_CLASS_MANIFEST, {})[0]
    findings = check_catalog_findings(catalog, env={})
    assert findings == []


def test_the_shipped_demo_manifest_reports_exactly_send_email_as_a_finding():
    """send_email is the one shipped tool with no data_class, and it is
    supposed to be that way (mail is a write). Everything else in the
    shipped manifest already declares one."""
    findings = check_catalog_findings(
        Path("demo/scenario/tools.toml"),
        env={"DOCSTORE_URL": "http://d", "DB_PATH": "data/customers.db",
             "MAILER_URL": "http://m"},
    )
    assert len(findings) == 1
    assert "send_email" in findings[0]


# --- --opa mode: reads data.tools from a running server --------------------
#
# The only one of check_catalog's three checks that had never been
# automated: offline comparisons are exercised throughout this file, but
# --opa's three branches (agrees, disagrees, undefined) were hand-verified
# only, even though it is the one check that can catch a bundle mounted
# where OPA namespaces the document away from data.tools -- no file
# comparison can see that -- and it ships in the product CLI.
# httpx.MockTransport stands in for the running server: check_catalog calls
# the module-level httpx.get(...), so the fake is installed there rather
# than threaded through as a client argument.


def _stub_opa_get(monkeypatch, *, result=None, raises: Exception | None = None) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/data/tools"
        return httpx.Response(200, json={"result": result})

    def fake_get(url: str, timeout: float = 5.0) -> httpx.Response:
        if raises is not None:
            raise raises
        return httpx.Client(transport=httpx.MockTransport(handler)).get(url)

    monkeypatch.setattr(httpx, "get", fake_get)


def test_opa_mode_reports_nothing_when_the_server_agrees(tmp_path, monkeypatch):
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    _stub_opa_get(monkeypatch, result={"read_document": {"target_kind": "doc"}})
    assert check_catalog(catalog, data, env={}, opa_url="http://opa:8181") == []


def test_opa_mode_reports_a_server_that_disagrees_with_the_data_file(tmp_path, monkeypatch):
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    _stub_opa_get(monkeypatch, result={"read_document": {"target_kind": "db"}})
    problems = check_catalog(catalog, data, env={}, opa_url="http://opa:8181")
    assert any("serves a different data.tools" in p for p in problems)


def test_opa_mode_reports_data_tools_undefined(tmp_path, monkeypatch):
    """The bundle-namespacing failure: mounted in a subdirectory, data.tools
    resolves to nothing at all rather than to a wrong value."""
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    _stub_opa_get(monkeypatch, result=None)
    problems = check_catalog(catalog, data, env={}, opa_url="http://opa:8181")
    assert any("data.tools is undefined" in p for p in problems)


def test_opa_mode_reports_a_connection_failure(tmp_path, monkeypatch):
    catalog, data = files(tmp_path, MANIFEST,
                          {"tools": {"read_document": {"target_kind": "doc"}}})
    _stub_opa_get(monkeypatch, raises=httpx.ConnectError("connection refused"))
    problems = check_catalog(catalog, data, env={}, opa_url="http://opa:8181")
    assert any("cannot read data.tools" in p for p in problems)
