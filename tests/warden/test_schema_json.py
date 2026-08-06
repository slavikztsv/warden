"""The advertised schema and the enforced one must agree, both ways."""

from __future__ import annotations

from types import MappingProxyType

import pytest
from jsonschema import Draft202012Validator

from warden.broker.config.loader import ConfigError
from warden.broker.config.schema import ArgSpec, ToolSchema
from warden.broker.schema_json import json_schema


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
    refuses to send at all -- silently, with no record anywhere.

    `sr` is the only required spec. ToolSchema.validate() (schema.py:86-97)
    iterates every spec in the schema, not just the keys present in the
    payload, so a payload missing `sr` forces enforced=False, and the
    generated schema's "required": ["sr"] forces advertised=False in
    lockstep -- regardless of how any OTHER key is mapped. A payload that
    omits `sr` therefore can't discriminate a wrong mapping on any other
    spec: both sides agree for the same reason (the missing key), not
    because the mapping under test is correct.

    So the majority of payloads below carry a valid "sr": "x" and vary
    exactly one other key -- that's what actually exercises non_empty,
    null_is_absent, and additionalProperties. A minority of payloads still
    omit `sr`, to keep the required-check itself covered.
    """
    specs = {
        "s": ArgSpec(type="string"),
        "sr": ArgSpec(type="string", required=True),
        "sn": ArgSpec(type="string", non_empty=True),
        "sz": ArgSpec(type="string", null_is_absent=True),
        "snz": ArgSpec(type="string", non_empty=True, null_is_absent=True),
        "a": ArgSpec(type="array", items="string"),
        "an": ArgSpec(type="array", items="string", non_empty=True),
        "anz": ArgSpec(type="array", items="string", non_empty=True, null_is_absent=True),
    }
    schema = build(specs)
    validator = Draft202012Validator(json_schema(schema))

    values = ["x", "", None, [], ["a"], ["a", 1], 42, {"k": "v"}]
    names = sorted(specs)
    non_required = [name for name in names if name != "sr"]

    payloads = []

    # Majority: sr present and valid, crossed with every non-required spec
    # over every value. This is what actually probes each mapping, because
    # the required-check on sr agrees on both sides before any other key is
    # considered -- so it can't mask a wrong mapping here. Covers, among
    # others, {"sr": "x", "sz": None} (null-with-sr), {"sr": "x", "s": None}
    # (null on a spec where null is NOT allowed), {"sr": "x", "sn": ""} and
    # {"sr": "x", "an": []} (non_empty violations), and the null_is_absent +
    # non_empty combinations via snz/anz.
    for name in non_required:
        for value in values:
            payloads.append({"sr": "x", name: value})

    # sr present with an unknown key alongside it: probes
    # additionalProperties without the required-check masking the result.
    payloads.append({"sr": "x", "unknown": "y"})

    # sr alone: baseline, satisfies required, nothing else present.
    payloads.append({"sr": "x"})

    # Minority: sr omitted, so the required-check itself stays covered, but
    # it no longer dominates the whole payload set.
    payloads.append({})
    payloads += [{"sr": value} for value in values]
    payloads.append({"unknown": "x"})

    disagreements = []
    for payload in payloads:
        enforced = schema.validate(payload)
        advertised = validator.is_valid(payload)
        if enforced != advertised:
            disagreements.append((payload, enforced, advertised))
    assert disagreements == []
