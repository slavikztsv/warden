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

from warden.broker.adapters.base import Adapter, ToolResult, ToolTarget, UnknownTool
from warden.broker.adapters.registry import ADAPTERS, TARGET_KIND_BY_ADAPTER, build_adapter
from warden.broker.config.loader import ConfigError, interpolate
from warden.broker.config.schema import ToolSchema, parse_tool_schema

# Every key a [tools.<tool>] table may carry. The [args] vocabulary and the
# [binding] keys each have an allowlist already (schema.py's _ARG_KEYS,
# _check_binding_keys below); the tool table itself had none, so a misspelt
# key was read by nobody and reported by nobody. With a tool description now
# reaching a model, a silently-dropped `descriptoin` is a tool the model
# will misuse.
_TOOL_KEYS = ("kind", "binding", "args", "unknown_args", "description", "title")


def _check_tool_keys(tool: str, table: dict) -> None:
    for key in table:
        if key not in _TOOL_KEYS:
            raise ConfigError(
                f"tool {tool!r}: unknown key {key!r}; "
                f"expected one of {sorted(_TOOL_KEYS)}"
            )


def _text(tool: str, table: dict, key: str) -> str:
    value = table.get(key, "")
    if not isinstance(value, str):
        raise ConfigError(f"tool {tool!r}: {key} must be a string")
    return value


@dataclass(frozen=True)
class CatalogEntry:
    kind: str
    target_kind: str
    schema: ToolSchema
    adapter: Adapter
    # Advertised to a model by the MCP surface, and unused by every other
    # caller. Empty is legal here and rejected by `warden config check` only
    # when that surface is switched on.
    description: str = ""
    title: str = ""

    # No __hash__ override needed here: ToolSchema.__hash__ (see schema.py)
    # is now well-defined, and `adapter` instances are plain objects with no
    # __eq__ of their own, so they keep object identity's default __hash__.
    # With every field hashable, the dataclass-generated __hash__ (frozen=True,
    # eq=True) -- hash((kind, target_kind, schema, adapter, description, title)) -- just works.


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
    """`where` names the tool this binding belongs to, so a missing ${VAR}
    reads as "tool 'some_tool': ${SOME_VAR} is not set" at boot rather than
    the bare, tool-less message interpolate() raises on its own -- the
    difference between one manifest to check and a deployment with a dozen
    tools sharing that same variable name."""
    resolved: dict[str, object] = {}
    for key, value in binding.items():
        try:
            if isinstance(value, str):
                resolved[key] = interpolate(value, env)
            elif isinstance(value, list):
                resolved[key] = [
                    interpolate(item, env) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                resolved[key] = value
        except ConfigError as exc:
            raise ConfigError(f"tool {where!r}: {exc}") from exc
    return resolved


def _check_binding_keys(tool: str, kind: str, binding: dict) -> None:
    """Every [binding] key must be one the adapter actually reads.

    Before the split, `data_class="pii"` was compiled straight into the
    broker's own source -- there was no key to misspell or drop. Moving it
    into config made it OMISSIBLE, and this is the guard that answers it: an
    adapter's __init__ reads binding keys with dict.get(...), so an unknown
    key (a typo, or a key that belongs to a different adapter kind) is not a
    KeyError anywhere -- it is silently IGNORED, the same way `unknown_args`
    schema.py exists to make impossible for [args] (see its own comment: "a
    typo that silently disables a check is precisely the failure this module
    exists to make impossible"). [binding] had no equivalent until now.
    Concretely: deleting a `data_class = "pii"` binding line, or misspelling
    it `dataclass`, used to load cleanly, report "config consistent", and
    produce a task that can never be tainted -- the PII-sink rule (R7 in
    authz.rego) has nothing to fire on if the task never holds pii to begin
    with. Each adapter class declares its own accepted keys via
    BINDING_KEYS (see broker/adapters/*.py), next to REQUIRED_ARGS.
    """
    allowed = ADAPTERS[kind].BINDING_KEYS
    for key in binding:
        if key not in allowed:
            raise ConfigError(
                f"tool {tool!r}: binding.{key!r} is not a recognised key for "
                f"adapter kind {kind!r}; expected one of {sorted(allowed)}"
            )


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
        _check_tool_keys(tool, table)
        kind = table.get("kind")
        # `not in` on a Mapping[str, str] proves this is one of the four literal
        # keys, hence a str -- but tomllib hands back Any, so the narrowing has
        # to be said out loud for the four uses below.
        if not isinstance(kind, str) or kind not in TARGET_KIND_BY_ADAPTER:
            raise ConfigError(
                f"tool {tool!r}: unknown adapter kind {kind!r}; "
                f"expected one of {sorted(TARGET_KIND_BY_ADAPTER)}"
            )
        binding = table.get("binding", {})
        if not isinstance(binding, dict):
            raise ConfigError(f"tool {tool!r}: [binding] must be a table")
        resolved_binding = _interpolate_binding(binding, env, tool)
        _check_binding_keys(tool, kind, resolved_binding)
        if kind == "mail":
            _check_mail_binding(tool, resolved_binding)
        entries[tool] = CatalogEntry(
            kind=kind,
            target_kind=TARGET_KIND_BY_ADAPTER[kind],
            schema=parse_tool_schema(table, tool),
            adapter=build_adapter(kind, resolved_binding, client),
            description=_text(tool, table, "description"),
            title=_text(tool, table, "title"),
        )
    return ToolCatalog(entries)
