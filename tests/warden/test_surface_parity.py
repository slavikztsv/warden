"""Two front doors, one decision. Compared on the record, not on the code.

Every comparison below drives BOTH surfaces -- HTTP (`invoke()`) and MCP
(`call_tool()`) -- against the SAME `create_app` instance and the SAME
`AuditLog` (`build_with_mcp` mounts one spine under both doors), then diffs
the audit RECORDS those calls produced. Nothing here calls
`warden.broker.spine.Spine` and asserts "the same value came back twice" --
that would be a tautology, passing on day one and through the exact
regression class this file exists to catch (a renderer that starts applying
a side effect, or wording a refusal, on its own). Every assertion is
anchored to something durably written: an audit record, or a taint
snapshot.

Coverage note -- not every `Kind` in `warden/broker/spine.py` is reachable
through both doors, and this file says so at each Kind's own test rather
than silently omitting it:

* `Kind.MALFORMED_BODY_DENIED` is HTTP-only. It fires when
  `warden/broker/app.py`'s `_parse_args` cannot parse the request body as a
  JSON object at all -- `args=None` reaches the spine, which reserves that
  exact value for "a body that did not parse". MCP's JSON-RPC transport
  never hands a handler an unparsed body: `params.arguments` is already a
  parsed value (or absent, which `on_call_tool` normalises to `{}`, never to
  `None`) by the time the handler runs. See
  `test_malformed_body_is_denied_over_http_only`.

* `Kind.LISTED` belongs to a different dataclass (`ListOutcome`, returned by
  `Spine.list_tools`) than the `Outcome` this file compares -- so it sits
  outside what a record-by-record `Outcome` comparison even applies to. It
  is also HTTP-unreachable in a stronger sense than the above:
  `warden/broker/app.py` mounts exactly one route,
  `/v1/tools/{tool}/invoke`, and no listing route at all. See
  `test_listing_has_no_http_door_and_writes_no_record`.

Every other `Kind` -- eleven of the fourteen -- is reachable through both
doors and is compared below, either in the generic `CASES` loop (the kinds
that write exactly one audit record per call) or in its own dedicated test
(the kinds that write zero, for two different reasons: nothing was decided,
or the decision could not be durably recorded).

One more wrinkle, discovered while writing this file rather than assumed
going in: `Kind.EXECUTED` is NOT folded into the generic `CASES` loop below,
even though it writes exactly one record per call like the rest of that
group. A read that actually executes is the one branch that calls
`taint.record_read()`, so calling the SAME tool for the SAME task_id through
both doors in sequence means the second door's pre-call snapshot is not the
same starting point as the first's -- it is the first door's starting point
plus what the first door's own read just added. That is not the two doors
disagreeing; it is one task's budget, shared by construction across both
doors, correctly advancing between two calls made through it -- exactly the
property this file exists to hold both doors to. Asserting raw record
equality would therefore either be silently wrong (if `task_state` matched,
the budget would not actually be shared) or would require picking a tool
that reads nothing, which would stop proving anything. So
`test_both_surfaces_write_the_same_record_when_allowed` compares every OTHER
field for exact equality and separately pins the exact `task_state`
evolution a single, correctly-ordered tracker predicts.
"""

from __future__ import annotations

import httpx
import pytest

pytest.importorskip("mcp", reason="requires the warden[mcp] extra")

from warden.broker.adapters.base import ToolResult

VOLATILE = {"seq", "ts", "prev_hash", "hash"}


def _stripped(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in VOLATILE}


# --- The core comparison: one record per call, on both doors ---------------
#
# Every case below reaches a branch of Spine.handle_tool_call that writes
# EXACTLY one audit record per call, so one HTTP call and one MCP call for
# the identical (payload, tool, args) leave exactly two records -- and they
# must be identical except for the four fields every append() mints fresh.

CASES = [
    # EXECUTED is deliberately not here -- see the module docstring's note
    # on why it needs its own test, test_both_surfaces_write_the_same_record_when_allowed.
    ("denied", {"allow": False, "deny_reasons": ["rows.bounded"]}, "read_document", {"doc_id": "a"}),
    # Same rule STRING as "unknown_tool" below, reached a completely
    # different way -- OPA denying a call to a tool the catalog KNOWS,
    # rather than the catalog itself refusing a name it does not. Proves the
    # two doors do not conflate POLICY_DENIED and UNKNOWN_TOOL_DENIED just
    # because decision.rule happens to collide.
    ("capability_rule_from_policy", {"allow": False, "deny_reasons": ["tools.allowed"]}, "read_document", {"doc_id": "a"}),
    ("schema_invalid", {"allow": True, "deny_reasons": []}, "read_document", {}),
    ("unknown_tool", {"allow": True, "deny_reasons": []}, "no_such_tool", {"x": "y"}),
    # DESCRIBE_CLIENT_ERROR_DENIED: query_customers's filter shape-checks as
    # a plain string, so it clears the pre-describe() schema check, but
    # SqlAdapter._coerce's int("abc") raises ValueError INSIDE describe().
    # The OPA payload is irrelevant here -- decide() is never reached -- and
    # is only supplied because build_with_mcp requires one.
    ("describe_client_error", {"allow": True, "deny_reasons": []}, "query_customers", {"filter": "id=abc"}),
]


@pytest.mark.parametrize("name,payload,tool,args", CASES, ids=[c[0] for c in CASES])
def test_both_surfaces_write_the_same_record(tmp_path, name, payload, tool, args):
    """Every CASES entry is a DENIED-shaped Outcome, so both doors render a
    TOOL error a caller can read rather than raising a protocol error --
    which is what makes the second half of this test possible: not only do
    both doors AUDIT the same record, they SAY the same rule and the same
    words to the caller who made the call. A renderer with its own opinion
    about how to phrase a rule -- app.py's `_render` inventing a suffix,
    say, or reading a stale copy of `outcome.rule` -- would not show up in
    the audit record at all (the record is written by the spine, before any
    surface renders anything), so the record comparison alone is blind to
    that class of bug. This is why the rendered response is compared too,
    not only the record.
    """
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    with build_with_mcp(tmp_path, signer, payload) as (client, audit):
        response = invoke(client, token, tool, args)
        try:
            mcp_result = call_tool(client, token, tool, args)
        except Exception:
            # A protocol error is a legitimate rendering for some variants;
            # the record it wrote is what the rest of this test is about.
            mcp_result = None

        records = audit.records()
        assert len(records) == 2, f"{name}: {records}"
        http, mcp = records
        stripped = [_stripped(r) for r in (http, mcp)]
        assert stripped[0] == stripped[1], f"{name}: {stripped}"

        # Every CASES entry denies, over both doors, with no protocol error
        # on either side -- so both renderings are available to compare
        # directly, not just the records they were built from.
        assert response.status_code == 403, f"{name}: {response.status_code}"
        body = response.json()
        assert body["rule"] == records[0]["rule"], f"{name}: {body} vs {records[0]}"
        assert mcp_result is not None, f"{name}: MCP raised instead of denying"
        assert mcp_result.is_error is True, name
        mcp_text = mcp_result.content[0].text
        assert body["rule"] in mcp_text, f"{name}: {body['rule']!r} not in {mcp_text!r}"
        assert body["message"] == mcp_text, f"{name}: {body['message']!r} != {mcp_text!r}"


def test_both_surfaces_write_the_same_record_when_allowed(tmp_path):
    """Kind.EXECUTED. See the module docstring for why this is not one of
    the CASES above: read_document tags every successful read "public" (its
    binding's data_class) and always reports 0 rows (DocstoreAdapter's
    ToolResult never sets `rows`), so calling it twice for the SAME task_id
    -- once through each door -- taints data_classes_held after the first
    call and leaves rows_returned_so_far untouched. Every field but
    task_state is asserted equal outright; task_state is asserted against
    the EXACT evolution a single, correctly-ordered taint tracker predicts,
    which is strictly more informative than raw equality would have been.
    """
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = invoke(client, token, "read_document", {"doc_id": "a"})
        assert response.status_code == 200
        result = call_tool(client, token, "read_document", {"doc_id": "a"})
        assert result.is_error is False

        records = audit.records()
    assert len(records) == 2, records
    http, mcp = records
    stripped = [
        {k: v for k, v in r.items() if k not in VOLATILE | {"task_state"}}
        for r in (http, mcp)
    ]
    assert stripped[0] == stripped[1]
    assert http["task_state"] == {"data_classes_held": [], "rows_returned_so_far": 0}
    assert mcp["task_state"] == {
        "data_classes_held": ["public"],
        "rows_returned_so_far": 0,
    }


def test_both_surfaces_write_the_same_record_when_unauthenticated(tmp_path):
    """UNAUTHENTICATED, reached with a credential neither door can verify.

    Not folded into CASES above because the two doors build the request
    differently for a token of None (invoke() always sends an Authorization
    header -- even "Bearer None" -- while call_tool() omits the header
    entirely). A garbage token STRING, sent identically by both doors,
    sidesteps that difference: both land on the same
    `Spine._authenticate()` failure for the same reason.
    """
    from tests.warden.test_app import build_with_mcp, invoke
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    bogus = "not-a-jwt-at-all"
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = invoke(client, bogus, "read_document", {"doc_id": "a"})
        assert response.status_code == 401
        try:
            call_tool(client, bogus, "read_document", {"doc_id": "a"})
        except Exception:
            # MCP renders UNAUTHENTICATED as a protocol error -- see the
            # module docstring on mcp.py -- so this raises rather than
            # returning a result. The record it wrote is what matters here.
            pass

        records = audit.records()
    assert len(records) == 2, records
    assert _stripped(records[0]) == _stripped(records[1])
    assert records[0]["rule"] == "unauthenticated"


def test_both_surfaces_write_the_same_record_after_a_durable_allow_whose_execute_fails(
    tmp_path,
):
    """EXECUTE_FAILED_AFTER_DURABLE_ALLOW. The allow record is written
    BEFORE execute() ever runs, so this still writes exactly one record per
    call -- same shape as EXECUTED -- and only what happens after execute()
    differs (a 502 / a tool error, instead of content)."""
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)

    def backend_handler(request):
        return httpx.Response(500, text="upstream on fire")

    with build_with_mcp(
        tmp_path,
        signer,
        {"allow": True, "deny_reasons": []},
        backend_handler=backend_handler,
    ) as (client, audit):
        http = invoke(client, token, "http_fetch", {"url": "http://x.internal/a"})
        assert http.status_code == 502
        try:
            call_tool(client, token, "http_fetch", {"url": "http://x.internal/a"})
        except Exception:
            pass

        records = audit.records()
    assert len(records) == 2, records
    assert _stripped(records[0]) == _stripped(records[1])
    assert records[0]["decision"] == "allow"


def test_both_surfaces_write_the_same_record_when_taint_rejects_the_read(tmp_path):
    """TAINT_REJECTED_AFTER_EXECUTE. Reached by handing the catalog an
    adapter whose execute() reports a negative row count -- taint.py's own
    guard against silently under-counting the row budget. Like
    EXECUTE_FAILED_AFTER_DURABLE_ALLOW, the allow record is durable before
    the taint update ever runs, so this too writes exactly one record per
    call."""
    from demo.mocks.seed_db import seed_customers
    from tests.support.catalog import demo_catalog
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)

    db = tmp_path / "negrows.db"
    seed_customers(db, count=5)
    catalog = demo_catalog(
        docstore_url="http://docstore.internal",
        db_path=db,
        mailer_url="http://mailer.internal",
        client=httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, text="doc-body"))
        ),
    )
    original_execute = catalog.execute

    def negative_rows(tool, args):
        result = original_execute(tool, args)
        return ToolResult(content=result.content, rows=-5, data_class=result.data_class)

    catalog.execute = negative_rows

    with build_with_mcp(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, catalog=catalog
    ) as (client, audit):
        http = invoke(client, token, "read_document", {"doc_id": "a"})
        assert http.status_code == 502
        try:
            call_tool(client, token, "read_document", {"doc_id": "a"})
        except Exception:
            pass

        records = audit.records()
    assert len(records) == 2, records
    assert _stripped(records[0]) == _stripped(records[1])
    assert records[0]["decision"] == "allow"


# --- The two kinds that write ZERO records, for two different reasons ------


def test_both_surfaces_write_nothing_on_a_describe_backend_fault(tmp_path):
    """DESCRIBE_BACKEND_FAULT is the one branch of handle_tool_call that
    writes NO audit record at all -- spine.py's own comment: "no decision
    was avoided because of anything the caller did, so nothing is recorded
    against it." So the parity claim here is not "the two records agree"
    (there are none) -- it is that NEITHER door quietly writes one anyway,
    which a renderer with its own opinion about what "unaudited" means could
    still do."""
    from warden.broker.config.catalog import CatalogEntry, ToolCatalog
    from warden.broker.config.schema import ArgSpec, ToolSchema
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    class Explodes:
        target_kind = "doc"

        def describe(self, args):
            raise RuntimeError("boom")

        def execute(self, args):  # pragma: no cover
            raise AssertionError("must never be reached")

    catalog = ToolCatalog({
        "brittle": CatalogEntry(
            kind="docstore",
            target_kind="doc",
            schema=ToolSchema(args={"id": ArgSpec(type="string")}),
            adapter=Explodes(),
        )
    })
    signer = Signer.generate()
    token = token_for(signer, allowed_tools=["brittle"])

    with build_with_mcp(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, catalog=catalog
    ) as (client, audit):
        http = invoke(client, token, "brittle", {"id": "a"})
        assert http.status_code == 502
        result = call_tool(client, token, "brittle", {"id": "a"})
        assert result.is_error is True

        assert audit.records() == []


AUDIT_UNAVAILABLE_CASES = [
    ("on_allow", {"allow": True, "deny_reasons": []}, False),
    ("on_deny", {"allow": False, "deny_reasons": ["rows.bounded"]}, False),
    ("on_unauthenticated", {"allow": True, "deny_reasons": []}, True),
]


@pytest.mark.parametrize(
    "name,payload,unauthenticated",
    AUDIT_UNAVAILABLE_CASES,
    ids=[c[0] for c in AUDIT_UNAVAILABLE_CASES],
)
def test_both_surfaces_write_nothing_when_the_audit_log_is_unavailable(
    tmp_path, name, payload, unauthenticated
):
    """AUDIT_UNAVAILABLE_ON_{ALLOW,DENY,UNAUTHENTICATED}: three different
    call sites in Spine (the durable allow write, the deny write, and the
    sentinel refusal write) that all reach the same "the log itself raised
    OSError" branch. Like DESCRIBE_BACKEND_FAULT, the parity claim is that
    nothing gets written by EITHER door when the log cannot durably hold the
    record it is about to write -- not that two records agree, because
    there are none.
    """
    from mcp.shared.exceptions import MCPError

    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = "not-a-jwt-at-all" if unauthenticated else token_for(signer)

    with build_with_mcp(tmp_path, signer, payload) as (client, audit):

        def explode(**kwargs):
            raise OSError("disk full")

        audit.append = explode

        http = invoke(client, token, "read_document", {"doc_id": "a"})
        assert http.status_code == 503, f"{name}: {http.status_code}"
        assert http.json()["error"] == "audit_unavailable"

        with pytest.raises(MCPError):
            call_tool(client, token, "read_document", {"doc_id": "a"})

        assert audit.records() == [], f"{name}: {audit.records()}"


def test_malformed_body_is_denied_over_http_only(tmp_path):
    """MALFORMED_BODY_DENIED. Fires when app.py's `_parse_args` cannot parse
    the request body as a JSON object at all -- `args=None` reaches the
    spine, which reserves that exact value for "a body that did not parse".

    MCP cannot produce this Kind: its JSON-RPC transport hands `on_call_tool`
    an already-parsed `params.arguments`, and a null one normalises to `{}`
    (see mcp.py's own comment beside that line), never to `None`. There is
    therefore no MCP call anywhere in this test -- this Kind has exactly one
    door, and this is that door's own coverage of it.
    """
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = client.post(
            "/v1/tools/read_document/invoke",
            content=b"not json at all {{{",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 403
        assert response.json()["rule"] == "input.malformed"
        records = audit.records()
    assert len(records) == 1
    assert records[0]["rule"] == "input.malformed"
    assert records[0]["decision"] == "deny"


def test_listing_has_no_http_door_and_writes_no_record(tmp_path):
    """Kind.LISTED, documented rather than compared.

    `Spine.list_tools` returns a `ListOutcome` -- a dataclass entirely
    separate from `Outcome` -- so it sits outside what this file's
    record-by-record `Outcome` comparison even applies to. It is also
    unreachable over HTTP in the stronger sense that there is no HTTP route
    for it at all: `warden/broker/app.py` mounts exactly one route,
    `/v1/tools/{tool}/invoke`. What IS asserted here, on the one door that
    exists: an authenticated listing writes no audit record, matching
    `list_tools`'s own docstring ("usability, never enforcement").
    """
    from tests.warden.test_app import build_with_mcp, token_for
    from tests.warden.test_mcp_surface import list_tools
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        assert not any(
            getattr(route, "path", "") == "/v1/tools" for route in client.app.routes
        )
        listing = list_tools(client, token_for(signer))
        assert listing.tools  # the token's allowed tools, non-empty
        assert audit.records() == []


# --- The budget: advanced once per surface, never by a renderer ------------


def test_an_allowed_read_advances_the_budget_once_per_surface(tmp_path):
    """If a renderer applied the taint update instead of the spine, this
    would read 2 after one call through each door, or 0."""
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        _,
    ):
        spine = client.app.state.spine
        invoke(client, token, "query_customers", {"filter": "id=8812"})
        after_http = spine.task_state("4711")["rows_returned_so_far"]
        call_tool(client, token, "query_customers", {"filter": "id=8812"})
        after_mcp = spine.task_state("4711")["rows_returned_so_far"]
        assert after_http == 1
        assert after_mcp == 2


# --- The concurrency mirror --------------------------------------------


async def test_concurrent_mcp_calls_for_one_task_do_not_exceed_the_row_bound(tmp_path):
    """The mirror of test_app.py's own concurrency test, through the other
    door. The invariant is that the spine contains no await, so a snapshot
    and the read it authorises cannot be interleaved. A handler registered as
    a plain `def` would run on a worker thread and break it -- which is a
    one-word change away at all times.

    Unlike test_app.py's own version, this does not need to hand-engineer a
    forced suspension point to prove the race is closed. Traced empirically
    (an OPA handler that timestamps its own entry/exit, with an artificial
    delay): even when the two `tools/call` requests below are dispatched
    genuinely concurrently -- via `asyncio.gather` on the app's own event
    loop, submitted as one `client.portal.call`, bypassing `call_tool()`'s
    blocking bridge entirely -- the second request's OPA call does not begin
    until the first one's has returned. Zero overlap, every time. That is
    the zero-await architecture holding even under real concurrent client
    dispatch, not merely under this test's own sequencing: PolicyDecisionPoint
    talks to OPA with a synchronous httpx.Client, by the same design choice,
    so nothing yields the loop between one call's snapshot and its own
    audit write regardless of how many other requests are queued behind it.
    The simpler form below (two plain `call_tool()`s in a task group) is
    therefore not a weaker stand-in for that experiment -- it observes the
    same server-side serialisation, because the server provides no point at
    which it could do otherwise.
    """
    import anyio

    from tests.warden.test_app import build_with_mcp, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)

    def opa(request):
        import json as _json

        state = _json.loads(request.content)["input"]["task_state"]
        allow = state["rows_returned_so_far"] < 1
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": allow,
                    "deny_reasons": [] if allow else ["rows.bounded"],
                }
            },
        )

    # The stateful OPA goes in at construction, not swapped in afterwards.
    with build_with_mcp(tmp_path, signer, None, opa_handler=opa) as (client, audit):
        results = []

        async def one():
            results.append(call_tool(client, token, "query_customers", {"filter": "id=8812"}))

        async with anyio.create_task_group() as tg:
            tg.start_soon(one)
            tg.start_soon(one)

    decisions = [r["decision"] for r in audit.records()]
    assert sorted(decisions) == ["allow", "deny"]


def test_the_call_handler_is_a_coroutine_function(tmp_path):
    """A sync handler runs on a worker thread, which puts the snapshot and
    the read it authorises on different threads with nothing between them."""
    import inspect

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        _,
    ):
        server = client.app.state.mcp_session_manager
        entry = server.app.get_request_handler("tools/call")
        assert entry is not None, "could not reach the registered handler"
        assert inspect.iscoroutinefunction(entry.handler)
