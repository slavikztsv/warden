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
    from demo.cli.explain import (
        NarratedAudit,
        NarratedBackends,
        NarratedPDP,
        NarratedTaskState,
    )

    db = tmp_path / "customers.db"
    seed_customers(db, count=5)
    signer = Signer.generate()

    def opa_handler(request):
        return httpx.Response(
            200, json={"result": {"allow": allow, "deny_reasons": [] if allow else ["rows.bounded"]}}
        )

    spine = Spine(
        verifier=Verifier(signer.public_key_pem()),
        # Wrapped, both of them. This file existed to catch a Narrated*
        # wrapper that forwards a SUBSET of an interface, and it was passing
        # a bare PolicyDecisionPoint and a bare AuditLog -- so two of the five
        # wrappers were exactly as uncovered as NarratedBackends had been.
        pdp=NarratedPDP(PolicyDecisionPoint(
            "http://opa:8181",
            client=httpx.Client(transport=httpx.MockTransport(opa_handler)),
        )),
        task_state=NarratedTaskState(InMemoryTaskStateStore()),
        audit=NarratedAudit(AuditLog(tmp_path / "audit.jsonl")),
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


def test_the_narrated_audit_forwards_every_method_the_spine_uses(tmp_path, capsys):
    """NarratedAudit wraps AuditLog, so it can rot the same way.

    Until now this file passed a bare AuditLog, so a method added to AuditLog
    would have broken `warden-demo explain` with a green suite -- the exact
    incident this module's docstring describes, for a different wrapper.
    """
    spine, token = _spine(tmp_path)
    spine.handle_tool_call(token, "read_document", {"doc_id": "a"})
    spine.list_tools(None)  # an unauthenticated listing: a second append path

    records = AuditLog(tmp_path / "audit.jsonl").records()
    assert [r["action"]["type"] for r in records] == ["tool_call", "tool_list"]
    assert AuditLog(tmp_path / "audit.jsonl").verify_chain() == (True, None)


def test_narrated_audit_narrates_a_mint_differently(tmp_path, capsys):
    """P2/B7's silent failure, made loud.

    NarratedAudit.append reads only seq/decision/rule/prev_hash/hash, and a
    mint record carries all five -- so nothing FORCES the mint branch. Without
    it the demo prints "⑧ THE DECISION IS RECORDED — BEFORE ANYTHING RUNS"
    inside stage ⓪, before stage ① exists, under a `why` claiming the write
    happens before the action executes, about a mint after which nothing
    executes. And --quiet-why would not hide it: only why() is gated on
    SHOW_WHY, while stage() and show() are not.
    """
    from demo.cli.explain import NarratedAudit
    from warden.broker.control import record_mint
    from warden.broker.identity import Signer, Verifier
    from warden.broker.record_fields import args_digest

    signer = Signer.generate()
    grant = dict(
        agent_id="triage-bot", task_id="4711", purpose="support-triage",
        allowed_tools=["read_document"], data_classes=["public"],
        counterparties=["customer:8812"],
    )
    token = Verifier(signer.public_key_pem()).verify(signer.mint(**grant))

    audit = NarratedAudit(AuditLog(tmp_path / "audit.jsonl"))
    record = record_mint(audit, token=token, request_digest=args_digest(grant))
    printed = capsys.readouterr().out

    assert record["seq"] == 1
    assert "THE DECISION IS RECORDED" not in printed
    assert "recorded as" in printed
    assert f"seq {record['seq']}" in printed


def test_steps_from_survives_a_record_with_no_tool(tmp_path):
    """Three record types carry no `action.tool` -- tool_list, mcp_handshake
    and B7's mint -- and _steps_from subscripted it unguarded for all three.

    Not a B7 workaround: it was already a KeyError for the two that shipped
    before. What B7 changed is that a demo run now produces one.
    """
    from demo.cli.explain import _steps_from

    log = AuditLog(tmp_path / "audit.jsonl")
    for action, target in (
        ({"type": "mint"}, {"kind": "token", "allowed_tools": ["read_document", "send_email"]}),
        ({"type": "tool_list"}, {"kind": "unknown"}),
        ({"type": "tool_call", "tool": "read_document"}, {"kind": "doc", "path": "ticket-4711"}),
    ):
        log.append(
            task_id="4711", agent_id="triage-bot", purpose="support-triage",
            action=action, target=target, args_digest="sha256:aaa",
            decision="allow", rule="allow",
            task_state={"data_classes_held": [], "rows_charged_so_far": 0},
            policy_bundle_digest="sha256:bbb",
        )

    steps = _steps_from(tmp_path)
    assert [s["tool"] for s in steps] == ["mint", "tool_list", "read_document"]
    # And the matrix names the grant the same way `warden replay` does, rather
    # than falling through _target_label's `str(kind)` to `mint(token)` -- a
    # grant rendered as a tool call against a resource, in the same column as
    # real calls.
    assert steps[0]["target"] == "2 tools"


def test_the_demo_opens_its_log_before_it_mints():
    """P2/B7's exit criterion, as the one thing about it a unit test can see.

    "The mint record appears in `warden replay` ABOVE the first tool call" is
    a fact about seq, and seq is allocated in file order -- so the demo's mint
    is first only because its AuditLog is opened before stage ⓪ rather than
    beside the app, 30 lines later, where it used to be. Move that line back
    down and the record is written after every tool call, the replay block at
    the end of the run stops leading with the grant, and nothing else fails:
    the chain still verifies, the counts still agree, and the demo still
    reports 8 records.

    A source-order assertion because the alternative is booting OPA. The
    end-to-end version is the manual gate (`warden-demo explain --quiet-why`
    reports 8 records, 3 refusals, 1 record read); this is what CI can hold.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[2] / "demo" / "cli" / "explain.py").read_text()
    opened = source.index("audit = NarratedAudit(AuditLog(tmp")
    minted = source.index("record_mint(audit, token=claims")
    # The broker app -- nothing can make a brokered call before this exists,
    # so a mint recorded above it is a mint recorded above every tool call.
    # Anchored on this rather than on stage("①"), which is defined far earlier
    # in the file inside NarratedLLM and says nothing about run order.
    broker_exists = source.index("app = create_app(")
    assert opened < minted < broker_exists
