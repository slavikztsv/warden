"""Cross-checks the tool catalog against the policy's data document.

tools.toml and data.json are authored independently on purpose: it is what
keeps R1b a real check on a broker that mislabels a target, rather than a
value compared with itself. The cost of that independence is drift, and drift
fails closed but SILENTLY -- a blanket input.malformed on every call to the
affected tool, visible only in production.

Two modes. Offline compares the files. --opa reads data.tools from a running
server, which is the only way to catch a bundle mounted where OPA namespaces
the document to data.deployment.tools; no file comparison can see that.

A third, unrelated-looking check rides along here too: every argument an
adapter dereferences unconditionally (args[name], not args.get(name, ...))
must be `required = true` in the schema, or describe() raises KeyError and
the broker's widened client-caused branch (broker/app.py) audits it as
input.malformed against the agent -- a config-authoring defect wearing an
agent-caused reason. Each adapter class names its own unconditionally-
dereferenced arguments via REQUIRED_ARGS (see broker/adapters/*.py); this
module resolves them off the constructed adapter instance and checks them
against the schema. broker/config/catalog.py's _check_mail_binding is the
load-time precedent for the same shape of bug (recipients_arg not in fields).
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


def _required_args_problems(catalog, catalog_path: Path) -> list[str]:
    problems: list[str] = []
    for tool in sorted(catalog.names()):
        entry = catalog.entry(tool)
        adapter = entry.adapter
        for attr in type(adapter).REQUIRED_ARGS:
            arg = getattr(adapter, attr)
            spec = entry.schema.args.get(arg)
            if spec is None or not spec.required:
                problems.append(
                    f"{tool}: arg {arg!r} is dereferenced unconditionally by "
                    f"{type(adapter).__name__}.describe() but is not "
                    f"`required = true` in {catalog_path.name}; a call that "
                    f"omits it raises KeyError there, which the broker "
                    f"audits as input.malformed against the agent -- a "
                    f"config-authoring defect, not the agent's doing"
                )
    return problems


def check_catalog(
    catalog_path: Path, data_path: Path, env: Mapping[str, str], *, opa_url: str | None = None
) -> list[str]:
    problems: list[str] = []
    catalog = load_catalog(catalog_path, env, client=None)
    document = json.loads(Path(data_path).read_text())

    problems.extend(_required_args_problems(catalog, catalog_path))

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
