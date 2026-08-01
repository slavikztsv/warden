"""The adapter-kind vocabulary, and the one place it meets the policy's.

tools.toml names adapter kinds; authz.rego names target kinds. The mapping
lived nowhere, and getting it wrong fails closed but silently: every call to
that tool denies input.malformed and the replay prints a bare `tool()`
because cli/warden.py matches no branch for an unrecognised kind.

tests/test_adapter_registry.py parses R0 out of the policy and asserts this
mapping's image equals it, so the two cannot drift apart unnoticed.
"""

from __future__ import annotations

from collections.abc import Mapping

TARGET_KIND_BY_ADAPTER: Mapping[str, str] = {
    "docstore": "doc",
    "sql": "db",
    "http": "http",
    "mail": "mail",
}

from warden.broker.adapters.docstore import DocstoreAdapter
from warden.broker.adapters.http import HttpAdapter
from warden.broker.adapters.mail import MailAdapter
from warden.broker.adapters.sql import SqlAdapter

ADAPTERS: dict[str, type] = {
    "docstore": DocstoreAdapter,
    "http": HttpAdapter,
    "mail": MailAdapter,
    "sql": SqlAdapter,
}


def build_adapter(kind: str, binding: dict, client):
    if kind not in ADAPTERS:
        raise KeyError(f"unknown adapter kind {kind!r}")
    return ADAPTERS[kind](binding=binding, client=client)
