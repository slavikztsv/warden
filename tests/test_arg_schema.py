"""Declarative validation must reproduce the hand-written checks exactly.

Every expectation here was measured against broker/app.py's
_args_are_well_shaped before it was replaced. Where they look inconsistent --
doc_id "" denied but filter "" allowed -- that inconsistency IS the behaviour,
and a uniform default in either direction changes what the broker permits.
"""

from __future__ import annotations

import pytest

from broker.config.loader import ConfigError
from broker.config.schema import ArgSpec, ToolSchema, parse_tool_schema

DEMO = {
    "read_document": {"doc_id": {"type": "string", "required": True, "non_empty": True}},
    "query_customers": {"filter": {"type": "string", "required": True}},
    "http_fetch": {
        "url": {"type": "string", "required": True, "non_empty": True},
        "body": {"type": "string", "required": False, "null_is_absent": True},
    },
    "send_email": {
        "to": {"type": "array", "items": "string", "required": True},
        "subject": {"type": "string", "required": True},
        "body": {"type": "string", "required": True},
    },
}


def schema(tool: str, unknown_args: str = "reject") -> ToolSchema:
    return parse_tool_schema({"args": DEMO[tool], "unknown_args": unknown_args}, tool)


@pytest.mark.parametrize(
    "tool,args,expected",
    [
        # --- reproduced from the measured truth table ---
        ("read_document", {"doc_id": "ticket-4711"}, True),
        ("read_document", {"doc_id": ""}, False),
        ("read_document", {"doc_id": None}, False),
        ("read_document", {}, False),
        ("read_document", {"doc_id": 123}, False),
        ("query_customers", {"filter": "id=8812"}, True),
        ("query_customers", {"filter": ""}, True),
        ("query_customers", {}, False),
        ("query_customers", {"filter": None}, False),
        ("http_fetch", {"url": "http://x/"}, True),
        ("http_fetch", {"url": "http://x/", "body": "payload"}, True),
        ("http_fetch", {"url": "http://x/", "body": None}, True),
        ("http_fetch", {"url": ""}, False),
        ("http_fetch", {"url": "http://x/", "body": 7}, False),
        ("send_email", {"to": ["customer:8812"], "subject": "s", "body": "b"}, True),
        ("send_email", {"to": [], "subject": "", "body": ""}, True),
        ("send_email", {"to": "customer:8812", "subject": "s", "body": "b"}, False),
        ("send_email", {"to": [1], "subject": "s", "body": "b"}, False),
        ("send_email", {"to": {"customer:8812": "x@evil"}, "subject": "s", "body": "b"}, False),
        # required *array* arg gets null -- mirrors the required-string case
        # above (query_customers filter: None). ArgSpec.accepts checks
        # `value is None` before branching on type, so string and array
        # share one null path today; this pins the array half of that
        # sharing so a future edit that splits the null check per type has
        # something to break.
        ("send_email", {"to": None, "subject": "s", "body": "b"}, False),
    ],
)
def test_matches_the_measured_behaviour(tool, args, expected):
    assert schema(tool).validate(args) is expected


def test_undeclared_args_are_rejected_by_default():
    """The live hole this closes: send_email posts the WHOLE args dict to the
    mailer, so cc/bcc ride along on a call whose audited target.recipients is
    the approved one. The policy judged one recipient set; the action used
    another. Measured: 200 OK, audited ["customer:8812"], mailer received the
    cc."""
    assert schema("send_email").validate(
        {"to": ["customer:8812"], "subject": "s", "body": "b",
         "cc": ["attacker@evil.example"]}
    ) is False


def test_undeclared_args_can_be_allowed_explicitly():
    assert schema("send_email", unknown_args="allow").validate(
        {"to": ["customer:8812"], "subject": "s", "body": "b", "cc": ["x"]}
    ) is True


def test_null_is_absent_governs_array_arguments_the_same_way_as_strings():
    """DEMO's only array field (send_email.to) is required and its
    null_is_absent is left at the default False, so the parametrized
    to: None case above denies -- but a hypothetical future edit that
    splits ArgSpec.accepts's null check per type and forgets to consult
    null_is_absent for the array branch would ALSO deny that case (False
    either way), so it wouldn't be caught there. Pin the case where the two
    diverge: an optional array field with null_is_absent explicitly True
    must accept null, exactly like http_fetch.body does for strings."""
    spec = parse_tool_schema(
        {"args": {"cc": {"type": "array", "items": "string",
                          "required": False, "null_is_absent": True}}},
        "t",
    )
    assert spec.validate({"cc": None}) is True
    assert spec.validate({"cc": ["x"]}) is True


def test_optional_array_still_rejects_null_when_null_is_absent_is_unset():
    """The other half of the pair above, so the default (permissive-by-omission
    is NOT the same as permissive-for-null) is pinned for arrays too, not just
    strings."""
    spec = parse_tool_schema(
        {"args": {"cc": {"type": "array", "items": "string", "required": False}}},
        "t",
    )
    assert spec.validate({"cc": None}) is False


def test_a_tool_with_no_args_table_is_a_config_error():
    """Never a vacuous schema. A missing or misspelled [tools.X.args] makes
    tomllib yield nothing silently, and a validator that then passes
    everything restores the exact divergence the app.py docstring exists to
    prevent."""
    with pytest.raises(ConfigError, match=r"declares no \[args\] table"):
        parse_tool_schema({"unknown_args": "reject"}, "read_document")


def test_an_empty_args_table_is_a_config_error():
    with pytest.raises(ConfigError, match=r"declares no \[args\] table"):
        parse_tool_schema({"args": {}}, "read_document")


def test_an_unknown_type_is_a_config_error():
    with pytest.raises(ConfigError, match=r"type must be one of"):
        parse_tool_schema({"args": {"filter": {"type": "integer"}}}, "query_customers")


def test_an_unknown_schema_key_is_a_config_error():
    """A typo silently disabling a check is the failure mode this whole file
    is guarding against."""
    with pytest.raises(ConfigError, match="nonempty"):
        parse_tool_schema(
            {"args": {"url": {"type": "string", "nonempty": True}}}, "http_fetch"
        )


def test_an_unknown_unknown_args_policy_is_a_config_error():
    with pytest.raises(ConfigError, match=r"unknown_args must be one of"):
        parse_tool_schema({"args": DEMO["read_document"], "unknown_args": "ignore"}, "x")


def test_array_without_items_is_a_config_error():
    with pytest.raises(ConfigError, match=r'items must be "string" for an array'):
        parse_tool_schema({"args": {"to": {"type": "array", "required": True}}}, "send_email")


def test_defaults_are_the_permissive_ones_that_match_today():
    spec = parse_tool_schema({"args": {"filter": {"type": "string"}}}, "t").args["filter"]
    assert spec == ArgSpec(type="string", items=None, required=False,
                           non_empty=False, null_is_absent=False)
