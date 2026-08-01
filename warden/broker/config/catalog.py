"""The tool catalog: what this deployment's tools are and how to reach them.

Replaces the compiled-in TOOLS tuple and the Backends class, which between
them knew four tool names, one hardcoded table name, one hardcoded column
name and a subject prefix.

Two membership checks stay SEPARATE, as they are in the code this replaces.
validate() DEFERS on a tool it does not know; describe() raises UnknownTool.
Collapsing them would change what an unrecognised tool is audited as -- from
tools.allowed with target.kind "unknown" to input.malformed -- and would merge
"a tool the broker never heard of" with "a tool whose target the broker
mislabelled" into a single reason.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from warden.broker.adapters.base import ToolResult, ToolTarget, UnknownTool
from warden.broker.adapters.registry import TARGET_KIND_BY_ADAPTER, build_adapter
from warden.broker.config.loader import ConfigError, interpolate
from warden.broker.config.schema import ToolSchema, parse_tool_schema


@dataclass(frozen=True)
class CatalogEntry:
    kind: str
    target_kind: str
    schema: ToolSchema
    adapter: object

    # No __hash__ override needed here: ToolSchema.__hash__ (see schema.py)
    # is now well-defined, and `adapter` instances are plain objects with no
    # __eq__ of their own, so they keep object identity's default __hash__.
    # With every field hashable, the dataclass-generated __hash__ (frozen=True,
    # eq=True) -- hash((kind, target_kind, schema, adapter)) -- just works.


class ToolCatalog:
    def __init__(self, entries: Mapping[str, CatalogEntry]) -> None:
        self._entries = dict(entries)

    def names(self) -> frozenset[str]:
        return frozenset(self._entries)

    def __contains__(self, tool: str) -> bool:
        return tool in self._entries

    def target_kind(self, tool: str) -> str:
        return self._entry(tool).target_kind

    def entry(self, tool: str) -> CatalogEntry:
        """The full entry -- kind, target_kind, schema and adapter.

        Exists for `warden config check` (broker/config/check.py), which
        needs a tool's adapter instance (to read REQUIRED_ARGS off it) and
        its ToolSchema (to check what the manifest marked required) -- more
        than target_kind() alone exposes. Everything else in this class
        exposes one fact at a time on purpose; this is the one place that
        legitimately needs the whole record.
        """
        return self._entry(tool)

    def _entry(self, tool: str) -> CatalogEntry:
        try:
            return self._entries[tool]
        except KeyError as exc:
            raise UnknownTool(tool) from exc

    def validate(self, tool: str, args: dict) -> bool:
        entry = self._entries.get(tool)
        if entry is None:
            # Defer. describe() performs the membership check and the broker
            # audits the result as tools.allowed.
            return True
        return entry.schema.validate(args)

    def describe(self, tool: str, args: dict) -> ToolTarget:
        return self._entry(tool).adapter.describe(args)

    def execute(self, tool: str, args: dict) -> ToolResult:
        return self._entry(tool).adapter.execute(args)


def _interpolate_binding(binding: dict, env: Mapping[str, str], where: str) -> dict:
    resolved = {}
    for key, value in binding.items():
        if isinstance(value, str):
            resolved[key] = interpolate(value, env)
        elif isinstance(value, list):
            resolved[key] = [
                interpolate(item, env) if isinstance(item, str) else item
                for item in value
            ]
        else:
            resolved[key] = value
    return resolved


def _check_mail_binding(tool: str, binding: dict) -> None:
    """The mail adapter's describe() reports recipients by reading
    args[recipients_arg] (default "to"); execute() only forwards keys named
    in binding.fields. If recipients_arg is not itself one of those fields,
    describe() audits a recipient set that execute() then silently drops from
    the wire on the way out -- an audit-says-one-thing/action-does-another
    mismatch of the same family as the cc fail-open closed for mail's fields
    allowlist. The manifest is the one place this can be caught before a
    call, so it is caught here, at load."""
    recipients_arg = binding.get("recipients_arg", "to")
    fields = binding.get("fields", [])
    if recipients_arg not in fields:
        raise ConfigError(
            f"tool {tool!r}: binding.recipients_arg {recipients_arg!r} is not "
            f"in binding.fields {fields!r}; describe() would report "
            f"recipients that execute() silently drops"
        )


def load_catalog(path: Path, env: Mapping[str, str], client) -> ToolCatalog:
    path = Path(path)
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"tool catalog not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    tools = document.get("tools", {})
    if not isinstance(tools, dict):
        raise ConfigError(f"{path}: [tools] must be a table")

    entries: dict[str, CatalogEntry] = {}
    for tool, table in tools.items():
        if not isinstance(table, dict):
            raise ConfigError(f"{path}: tool {tool!r} must be a table")
        kind = table.get("kind")
        if kind not in TARGET_KIND_BY_ADAPTER:
            raise ConfigError(
                f"tool {tool!r}: unknown adapter kind {kind!r}; "
                f"expected one of {sorted(TARGET_KIND_BY_ADAPTER)}"
            )
        binding = table.get("binding", {})
        if not isinstance(binding, dict):
            raise ConfigError(f"tool {tool!r}: [binding] must be a table")
        resolved_binding = _interpolate_binding(binding, env, tool)
        if kind == "mail":
            _check_mail_binding(tool, resolved_binding)
        entries[tool] = CatalogEntry(
            kind=kind,
            target_kind=TARGET_KIND_BY_ADAPTER[kind],
            schema=parse_tool_schema(table, tool),
            adapter=build_adapter(kind, resolved_binding, client),
        )
    return ToolCatalog(entries)
