"""Cross-checks the tool catalog against the policy's data document.

tools.toml and data.json are authored independently on purpose: it is what
keeps R1b a real check on a broker that mislabels a target, rather than a
value compared with itself. The cost of that independence is drift, and drift
fails closed but SILENTLY -- a blanket input.malformed on every call to the
affected tool, visible only in production.

Two modes. Offline compares the files. --opa reads data.tools from a running
server, which is the only way to catch a bundle mounted where OPA namespaces
the document to data.deployment.tools; no file comparison can see that.

A third, unrelated-looking check rides along here too, over every binding
value that names an argument (a `binding.arg`, `binding.filter_arg`,
`binding.url_arg`, ... -- see each adapter's ARG_ATTRS in broker/adapters/*.py):

  * it must name a key [tools.<tool>.args] actually declares. Otherwise --
    with the schema's default unknown_args = "reject" -- no valid call can
    EVER populate that key, so the adapter silently falls back to its "no
    value" default on every single call. For SqlAdapter that default is "no
    filter": a binding.filter_arg the schema does not declare turns every
    call into an unfiltered full-table read, judged by policy as if it were
    a deliberate, scoped query.
  * if it is dereferenced unconditionally (args[name], not
    args.get(name, ...)) it must additionally be `required = true`, or
    describe() -- or, for DocstoreAdapter, execute(), which dereferences
    args[self._arg] where describe() only does args.get(self._arg, "") --
    raises KeyError. A describe()-time KeyError is caught by the broker's
    widened client-caused branch (broker/app.py) and audited as
    input.malformed against the agent, a config-authoring defect wearing an
    agent-caused reason. An execute()-time KeyError is worse: describe() and
    the policy decision built on it already SUCCEEDED, so the allow is
    durably audited before execute() ever raises -- the log then asserts an
    authorised read that never actually happened.

Each adapter class names its own argument-valued attributes via ARG_ATTRS,
and the unconditionally-dereferenced subset via REQUIRED_ARGS (describe-time)
and EXECUTE_REQUIRED_ARGS (execute-time) -- see broker/adapters/*.py; this
module resolves them off the constructed adapter instance and checks them
against the schema. broker/config/catalog.py's _check_mail_binding and
_check_binding_keys are the load-time precedents for the same shape of bug
(recipients_arg not in fields; an unrecognised [binding] key entirely).

A fourth check is advisory rather than a hard failure: check_catalog_findings
(below) reports a tool whose binding declares no data_class. That is not
always wrong -- a write-only tool (a mail-send, say) legitimately has none --
but on a tool whose result feeds back into the task (a read), it means that
read can never taint the task (see broker/taint.py), and a task that never
becomes tainted cannot be stopped by the PII-sink rule (R7 in authz.rego).
Kept out of check_catalog's own return value on purpose: unlike everything
else in this module, this one must never turn a legitimately-write-only
tool's config into a failing `warden config check`.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import httpx

from warden.broker.adapters.registry import TARGET_KIND_BY_ADAPTER
from warden.broker.config.catalog import load_catalog


def _policy_tools(document: Mapping) -> dict:
    tools = document.get("tools")
    return tools if isinstance(tools, dict) else {}


def _arg_binding_problems(catalog, catalog_path: Path) -> list[str]:
    problems: list[str] = []
    for tool in sorted(catalog.names()):
        entry = catalog.entry(tool)
        adapter = entry.adapter
        cls = type(adapter)
        required_attrs = set(cls.REQUIRED_ARGS) | set(cls.EXECUTE_REQUIRED_ARGS)
        every_arg_attr = sorted(required_attrs | set(cls.ARG_ATTRS))
        for attr in every_arg_attr:
            arg = getattr(adapter, attr)
            spec = entry.schema.args.get(arg)
            if spec is None:
                problems.append(
                    f"{tool}: binding names arg {arg!r} (via {cls.__name__}"
                    f".{attr}) that {catalog_path.name}'s [tools.{tool}.args] "
                    f"does not declare at all; with unknown_args=\"reject\" "
                    f"no valid call can ever populate it, so the adapter "
                    f"silently falls back to its default on every call"
                )
                continue
            if attr in required_attrs and not spec.required:
                stage = "describe()" if attr in cls.REQUIRED_ARGS else "execute()"
                problems.append(
                    f"{tool}: arg {arg!r} is dereferenced unconditionally by "
                    f"{cls.__name__}.{stage} but is not `required = true` in "
                    f"{catalog_path.name}; a call that omits it raises "
                    f"KeyError there, which the broker audits as "
                    f"input.malformed against the agent -- a config-authoring "
                    f"defect, not the agent's doing"
                )
    return problems


def _data_class_findings(catalog) -> list[str]:
    """Advisory, not a hard failure -- see this module's own docstring."""
    findings: list[str] = []
    for tool in sorted(catalog.names()):
        entry = catalog.entry(tool)
        if entry.adapter.data_class is None:
            findings.append(
                f"{tool}: binding declares no data_class, so this tool's "
                f"results can never taint the task and the PII-sink rule "
                f"(R7) can never fire on anything that follows a call to it. "
                f"Correct if {tool!r} is write-only (e.g. a mail send); a "
                f"bug if it reads data back into the task."
            )
    return findings


def check_catalog_findings(catalog_path: Path, env: Mapping[str, str]) -> list[str]:
    """Non-blocking findings about an otherwise-consistent catalog. Callers
    should print these but must NOT treat them as reasons to fail -- that is
    what separates this from check_catalog's `problems`."""
    catalog = load_catalog(catalog_path, env, client=None)
    return _data_class_findings(catalog)


def check_catalog(
    catalog_path: Path, data_path: Path, env: Mapping[str, str], *, opa_url: str | None = None
) -> list[str]:
    problems: list[str] = []
    catalog = load_catalog(catalog_path, env, client=None)
    document = json.loads(Path(data_path).read_text())

    problems.extend(_arg_binding_problems(catalog, catalog_path))

    declared = _policy_tools(document)
    if not declared:
        problems.append(f"{data_path}: no `tools` map; every tool_call will deny")

    for tool in sorted(catalog.names()):
        expected = catalog.target_kind(tool)
        entry = declared.get(tool)
        if not isinstance(entry, dict) or "target_kind" not in entry:
            problems.append(
                f"{tool}: declared in {catalog_path.name} but absent from "
                f"{data_path.name}; every call will deny input.malformed"
            )
            continue
        actual = entry["target_kind"]
        if actual == expected:
            continue
        if actual in TARGET_KIND_BY_ADAPTER:
            problems.append(
                f"{tool}: target_kind {actual!r} is an ADAPTER kind; the policy "
                f"expects the TARGET kind {expected!r}"
            )
        else:
            problems.append(
                f"{tool}: target_kind is {actual!r}, adapter produces {expected!r}"
            )

    for tool in sorted(set(declared) - set(catalog.names())):
        problems.append(f"{tool}: in {data_path.name} but not in {catalog_path.name}")

    if opa_url:
        try:
            response = httpx.get(f"{opa_url.rstrip('/')}/v1/data/tools", timeout=5.0)
            served = response.json().get("result")
        except (httpx.HTTPError, ValueError) as exc:
            problems.append(f"{opa_url}: cannot read data.tools ({exc})")
        else:
            if served is None:
                problems.append(
                    f"{opa_url}: data.tools is undefined. The bundle is probably "
                    "mounted in a subdirectory -- OPA namespaces a data file by "
                    "its path under the bundle root, so /policies/data/data.json "
                    "loads as data.data.tools."
                )
            elif served != declared:
                problems.append(f"{opa_url}: serves a different data.tools than {data_path}")
    return problems
