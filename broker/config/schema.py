"""Declarative argument validation.

broker/app.py's docstring states the invariant this upholds: args are
shape-checked BEFORE describe() is called, so describe() (which decides what
gets audited and policy-checked) and execute() (which acts) are guaranteed to
interpret the same args the same way. Its worked example is a bare string
where send_email expects a list -- read character-by-character by one stage
and whole by the other.

Moving that check into config makes it OMISSIBLE, which is the new risk. Two
rules answer it: a tool with no args table is a ConfigError rather than a
permissive default, and an unrecognised schema key is a ConfigError rather
than an ignored typo. Both fail at load, before the process serves anything.

The vocabulary is five keys because five keys reproduce the measured
behaviour exactly. It is deliberately not a general JSON-Schema subset:
`required` here mirrors what the old check demanded, NOT what an adapter can
default. query_customers with {} is denied today even though both stages fall
back to "all", and relaxing that turns a refusal into a full-table COUNT
judged by policy -- an allow on any deployment whose table is under the row
limit and whose token names no counterparties.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from broker.config.loader import ConfigError

_TYPES = ("string", "array")
_ARG_KEYS = ("type", "items", "required", "non_empty", "null_is_absent")
_UNKNOWN_ARGS_POLICIES = ("reject", "allow")


@dataclass(frozen=True)
class ArgSpec:
    type: str
    items: str | None = None
    required: bool = False
    non_empty: bool = False
    # JSON null validates and reaches execute() as None. Set only where a
    # stage branches on `is None` -- http_fetch.body selects GET vs POST that
    # way, so rejecting null there turns a working GET into input.malformed.
    null_is_absent: bool = False

    def accepts(self, value: object) -> bool:
        if value is None:
            return self.null_is_absent
        if self.type == "string":
            if not isinstance(value, str):
                return False
            return not (self.non_empty and value == "")
        # array
        if not isinstance(value, list):
            return False
        if self.items == "string" and not all(isinstance(item, str) for item in value):
            return False
        return not (self.non_empty and not value)


@dataclass(frozen=True)
class ToolSchema:
    args: Mapping[str, ArgSpec]
    unknown_args: str = "reject"

    def validate(self, args: dict) -> bool:
        if self.unknown_args == "reject":
            if any(name not in self.args for name in args):
                return False
        for name, spec in self.args.items():
            if name not in args:
                if spec.required:
                    return False
                continue
            if not spec.accepts(args[name]):
                return False
        return True


def _bool(table: dict, key: str, where: str) -> bool:
    value = table.get(key, False)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} must be true or false")
    return value


def parse_tool_schema(table: dict, tool: str) -> ToolSchema:
    raw_args = table.get("args")
    if not isinstance(raw_args, dict) or not raw_args:
        # Never a vacuous schema: a missing or misspelled [tools.X.args] makes
        # tomllib yield nothing silently, and a validator that then passes
        # everything reopens the divergence app.py exists to prevent.
        raise ConfigError(f"tool {tool!r} declares no [args] table")

    unknown_args = table.get("unknown_args", "reject")
    if unknown_args not in _UNKNOWN_ARGS_POLICIES:
        raise ConfigError(
            f"tool {tool!r}: unknown_args must be one of {_UNKNOWN_ARGS_POLICIES}"
        )

    specs: dict[str, ArgSpec] = {}
    for name, spec_table in raw_args.items():
        where = f"{tool}.args.{name}"
        if not isinstance(spec_table, dict):
            raise ConfigError(f"{where} must be a table")
        for key in spec_table:
            if key not in _ARG_KEYS:
                # A typo that silently disables a check is precisely the
                # failure this module exists to make impossible.
                raise ConfigError(f"{where}: unknown key {key!r}")
        arg_type = spec_table.get("type")
        if arg_type not in _TYPES:
            raise ConfigError(f"{where}.type must be one of {_TYPES}")
        items = spec_table.get("items")
        if arg_type == "array":
            if items != "string":
                raise ConfigError(f'{where}.items must be "string" for an array')
        elif items is not None:
            raise ConfigError(f"{where}.items is only meaningful for an array")
        specs[name] = ArgSpec(
            type=arg_type,
            items=items,
            required=_bool(spec_table, "required", where),
            non_empty=_bool(spec_table, "non_empty", where),
            null_is_absent=_bool(spec_table, "null_is_absent", where),
        )
    return ToolSchema(args=MappingProxyType(specs), unknown_args=unknown_args)
