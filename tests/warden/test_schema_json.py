"""The advertised schema and the enforced one must agree, both ways."""

from __future__ import annotations

import itertools

import pytest
from jsonschema import Draft202012Validator

from warden.broker.config.loader import ConfigError
from warden.broker.config.schema import ArgSpec, ToolSchema
from warden.broker.schema_json import json_schema
from types import MappingProxyType


def build(args: dict, unknown_args: str = "reject") -> ToolSchema:
    return ToolSchema(args=MappingProxyType(args), unknown_args=unknown_args)


def test_a_required_string_maps():
    schema = build({"doc_id": ArgSpec(type="string", required=True, non_empty=True)})
    assert json_schema(schema) == {
        "type": "object",
        "properties": {"doc_id": {"type": "string", "minLength": 1}},
        "required": ["doc_id"],
        "additionalProperties": False,
    }


def test_an_array_of_strings_maps():
    schema = build({"to": ArgSpec(type="array", items="string", required=True)})
    assert json_schema(schema)["properties"]["to"] == {
        "type": "array",
        "items": {"type": "string"},
    }


def test_null_is_absent_widens_the_type_rather_than_using_nullable():
    """2020-12 has no `nullable`. OpenAPI's spelling would be TIGHTER than
    accepts(), which returns True for None when this flag is set."""
    schema = build({"body": ArgSpec(type="string", null_is_absent=True)})
    assert json_schema(schema)["properties"]["body"]["type"] == ["string", "null"]


def test_unknown_args_allow_opens_additional_properties():
    schema = build({"x": ArgSpec(type="string")}, unknown_args="allow")
    assert json_schema(schema)["additionalProperties"] is True


def test_an_unmappable_type_raises_rather_than_emitting_an_empty_schema():
    """_TYPES is closed at two members today. A third added later must fail
    loudly here, not silently advertise a schema that permits anything."""
    schema = build({"x": ArgSpec(type="number")})
    with pytest.raises(ConfigError, match="number"):
        json_schema(schema)


def test_the_generated_schema_and_accepts_agree_in_both_directions():
    """The property test. A schema looser than accepts() produces calls the
    broker denies as input.malformed; a tighter one produces calls the client
    refuses to send at all -- silently, with no record anywhere."""
    specs = {
        "s": ArgSpec(type="string"),
        "sr": ArgSpec(type="string", required=True),
        "sn": ArgSpec(type="string", non_empty=True),
        "sz": ArgSpec(type="string", null_is_absent=True),
        "a": ArgSpec(type="array", items="string"),
        "an": ArgSpec(type="array", items="string", non_empty=True),
    }
    schema = build(specs)
    validator = Draft202012Validator(json_schema(schema))

    values = ["x", "", None, [], ["a"], ["a", 1], 42, {"k": "v"}]
    names = sorted(specs)
    # Every one-key payload, plus the empty one and a two-key one, over every
    # value. Enough to exercise required/non_empty/null/type in combination
    # without enumerating 8**6.
    payloads = [{}]
    for name in names:
        payloads += [{name: value} for value in values]
    for a, b in itertools.combinations(names, 2):
        payloads += [{a: "x", b: "y"}, {a: None, b: []}]
    payloads += [{"unknown": "x"}]

    disagreements = []
    for payload in payloads:
        enforced = schema.validate(payload)
        advertised = validator.is_valid(payload)
        if enforced != advertised:
            disagreements.append((payload, enforced, advertised))
    assert disagreements == []
