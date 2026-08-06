"""The narrated demo's wrappers, driven through a real spine.

`warden-demo explain` narrates by WRAPPING the real components rather than
reimplementing them -- that is what lets its output claim to be what actually
happened. The cost is that each wrapper forwards a hand-written subset of an
interface, and a subset breaks silently the moment the interface grows.

It did. P2·A added `ToolCatalog.data_class()`, which the spine calls on every
tool call; `NarratedBackends` was not given it. Every brokered call in the
narrated demo then raised AttributeError inside the spine's describe() guard,
which reported it as a 502 backend fault and recorded nothing -- so the demo
ran to completion showing "tool calls refused: 0", "customer records read: 0"
and "no records for that task", with 753 tests green. Nothing drove these
wrappers through a spine, so nothing noticed.

One executed call is enough to catch that whole class of defect, because
every wrapper sits on the path of every call.
"""

from __future__ import annotations

import httpx

from demo.mocks.seed_db import seed_customers
from tests.support.catalog import demo_catalog
from warden.broker.audit import AuditLog
from warden.broker.identity import Signer, Verifier
from warden.broker.pdp import PolicyDecisionPoint
from warden.broker.spine import Kind, Spine
from warden.broker.taint import InMemoryTaskStateStore


def _spine(tmp_path, *, allow=True):
    from demo.cli.explain import NarratedBackends, NarratedTaskState

    db = tmp_path / "customers.db"
    seed_customers(db, count=5)
    signer = Signer.generate()

    def opa_handler(request):
        return httpx.Response(
            200, json={"result": {"allow": allow, "deny_reasons": [] if allow else ["rows.bounded"]}}
        )

    spine = Spine(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181",
            client=httpx.Client(transport=httpx.MockTransport(opa_handler)),
        ),
        task_state=NarratedTaskState(InMemoryTaskStateStore()),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        catalog=NarratedBackends(
            demo_catalog(
                docstore_url="http://docstore.internal",
                db_path=db,
                mailer_url="http://mailer.internal",
                client=httpx.Client(
                    transport=httpx.MockTransport(
                        lambda r: httpx.Response(200, text="doc-body")
                    )
                ),
            )
        ),
        policy_digest="sha256:test",
        clock=lambda: 1_000,
    )
    token = signer.mint(
        agent_id="triage-bot",
        task_id="4711",
        purpose="support-triage",
        allowed_tools=["read_document", "query_customers"],
        data_classes=["public"],
        counterparties=["customer:8812"],
    )
    return spine, token


def test_a_brokered_call_executes_through_the_narrated_wrappers(tmp_path, capsys):
    """The regression test proper: an allowed call must EXECUTE, not fault.

    Asserting the Kind rather than merely "no exception" is what makes this
    catch the real failure, which was not a crash -- the spine swallowed the
    AttributeError into DESCRIBE_BACKEND_FAULT and returned a tidy 502.
    """
    spine, token = _spine(tmp_path)
    outcome = spine.handle_tool_call(token, "read_document", {"doc_id": "a"})
    assert outcome.kind is Kind.EXECUTED, outcome.message


def test_the_narrated_run_still_charges_and_settles_task_state(tmp_path, capsys):
    """NarratedTaskState wraps the store the same way, so it can break the
    same way. A read that executes must leave the task holding its class."""
    spine, token = _spine(tmp_path)
    spine.handle_tool_call(token, "query_customers", {"filter": "id=8812"})
    state = spine.task_state("4711")
    assert state["data_classes_held"] == ["pii"]
    assert state["rows_charged_so_far"] == 1


def test_a_denied_call_narrates_and_leaves_no_trace(tmp_path, capsys):
    """The settle path through the wrapper, too: release must reach the real
    store, or a refused call would keep holding budget it never spent."""
    spine, token = _spine(tmp_path, allow=False)
    outcome = spine.handle_tool_call(token, "query_customers", {"filter": "all"})
    assert outcome.kind is Kind.POLICY_DENIED
    assert spine.task_state("4711") == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }
