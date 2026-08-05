"""The argument vocabulary, as a schema a client can check against.

One source. The broker enforces ToolSchema.accepts(); a client checks the
JSON Schema this produces. If the two disagree, one of two things happens and
both are bad: a looser schema produces calls the broker refuses as malformed,
and a tighter one produces calls the client declines to send at all --
silently, with no record on either side.

The mapping is total because the parser closes the vocabulary: there are
exactly two types, and an array's items are always strings. A third type
added later must raise here rather than emit a permissive default, which is
why there is no fallback branch.
"""

from __future__ import annotations

from warden.broker.config.loader import ConfigError
from warden.broker.config.schema import ArgSpec, ToolSchema


def _property(name: str, spec: ArgSpec) -> dict:
    if spec.type == "string":
        node: dict = {"type": "string"}
        if spec.non_empty:
            node["minLength"] = 1
    elif spec.type == "array":
        node = {"type": "array", "items": {"type": "string"}}
        if spec.non_empty:
            node["minItems"] = 1
    else:
        raise ConfigError(
            f"argument {name!r}: type {spec.type!r} has no JSON Schema mapping"
        )
    if spec.null_is_absent:
        # A type array, not OpenAPI's `nullable: true`, which 2020-12 does
        # not have and which would be tighter than accepts() -- that returns
        # True for None before it ever reaches the non_empty check. The
        # minLength/minItems above stay: 2020-12 applies them only to strings
        # and arrays, so null still validates.
        node["type"] = [node["type"], "null"]
    return node


def json_schema(schema: ToolSchema) -> dict:
    return {
        "type": "object",
        "properties": {
            name: _property(name, spec) for name, spec in schema.args.items()
        },
        "required": sorted(
            name for name, spec in schema.args.items() if spec.required
        ),
        "additionalProperties": schema.unknown_args == "allow",
    }
