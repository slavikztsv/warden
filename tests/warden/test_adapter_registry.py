"""The two kind vocabularies must not drift.

tools.toml says http/sql/docstore/mail; authz.rego says doc/db/http/mail.
Writing "sql" where the policy expects "db" yields a defined, is_string
value matching no target kind, so every call to that tool denies
input.malformed -- closed, but silently -- and cli/warden.py's _describe
matches no branch and prints a bare `query_customers()`, dropping the row
count that carries the whole rows.bounded demonstration.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from warden.broker.adapters.base import ToolTarget
from warden.broker.adapters.registry import ADAPTERS, TARGET_KIND_BY_ADAPTER, build_adapter

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def policy_target_kinds() -> set[str]:
    source = (REPO_ROOT / "warden" / "policies" / "authz.rego").read_text()
    return set(re.findall(r'not input\.target\.kind == "([a-z_]+)"', source))


def test_the_mapping_image_is_exactly_what_the_policy_accepts():
    assert set(TARGET_KIND_BY_ADAPTER.values()) == policy_target_kinds()


def test_every_adapter_kind_maps_to_something():
    assert TARGET_KIND_BY_ADAPTER == {
        "docstore": "doc", "sql": "db", "http": "http", "mail": "mail",
    }


def test_target_kind_by_adapter_agrees_with_each_adapter_classs_own_attribute():
    """TARGET_KIND_BY_ADAPTER and each adapter class's own `target_kind`
    class attribute are two hand-written literals pinned to the same values,
    but not to EACH OTHER -- nothing stopped one from drifting while the
    other stayed put. This links them structurally."""
    assert {kind: cls.target_kind for kind, cls in ADAPTERS.items()} == dict(
        TARGET_KIND_BY_ADAPTER
    )


def test_building_an_unknown_kind_is_an_error():
    with pytest.raises(KeyError, match="nosuchkind"):
        build_adapter("nosuchkind", {}, client=None)


def test_tool_target_as_dict_key_order_is_unchanged():
    """The audit file is written key-sorted now, but describe() output is
    compared field-by-field in the golden tests, and _describe reads specific
    keys. Pin the full shape."""
    assert ToolTarget(kind="doc", path="x").as_dict() == {
        "kind": "doc", "host": "", "port": 0, "path": "x",
        "estimated_rows": 0, "recipients": [], "subjects": [],
    }
