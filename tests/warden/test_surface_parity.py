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

* `Kind.MALFORMED_BODY_DENIED` is HTTP-only. `warden/broker/app.py`'s
  `_parse_args` produces its reserved `args=None` for TWO different HTTP
  inputs: a body that is not parseable JSON at all (see
  `test_malformed_body_is_denied_over_http_only`), and a well-formed body
  carrying an EXPLICIT `"args": null` -- `body.get("args", {})` returns the
  literal `None` in that case, not the `{}` default, because the key is
  present. MCP's JSON-RPC transport never hands a handler an unparsed body,
  so the first case has no MCP side to compare against at all. The second
  --  `"arguments": null`, explicit -- does have an MCP equivalent, and
  IT IS NOT BENIGN, despite once being described that way here: `on_call_tool`
  normalises a null (or absent) `arguments` to `{}` BEFORE calling the
  spine, so the call is judged on the tool's actual schema like any other
  MCP call, landing on `Kind.SCHEMA_INVALID_DENIED` rather than
  `Kind.MALFORMED_BODY_DENIED`. For the shipped demo catalog, where every
  tool requires at least one argument, that distinction is invisible in the
  audit record: `MALFORMED_BODY_DENIED` and `SCHEMA_INVALID_DENIED` share
  the same rule string (`MALFORMED = "input.malformed"`, spine.py) and both
  digest `{}`, so the two records come out byte-identical despite being two
  different `Kind`s under the hood. For a tool whose schema has NO required
  arguments, though, the two diverge in OUTCOME, not merely in internal
  labelling: HTTP's `MALFORMED_BODY_DENIED` denies unconditionally, never
  consulting the schema, while MCP's normalised `{}` PASSES that schema and
  the call proceeds to `describe()`/`decide()`/`execute()` -- allowed and
  executed, if policy permits, for the exact request HTTP flatly refused.
  Measured, not hypothetical: any deployment's catalog may define a tool
  with no required arguments (the shipped one happens not to). Pinned by
  `test_explicit_null_args_is_denied_on_http_and_can_execute_on_mcp` and
  documented in docs/THREAT_MODEL.md, next to the non-object-arguments case
  below, which it sits right beside.

  A DIFFERENT, REAL divergence sits right next to it, and is not benign
  either: `arguments` of a well-formed but NON-OBJECT type (a string, a
  list, ...) is rejected by the SDK's own pydantic validation before ANY
  handler runs -- -32602, zero audit records -- while the identical caller
  mistake on the HTTP door (`args` as a non-dict) is denied and AUDITED as
  input.malformed, the same as the null-body case above. This is reachable
  by any MCP client today, not a hypothetical: the two doors do not agree
  on whether the attempt is recorded at all. Pinned, not glossed over, by
  `test_non_object_arguments_are_recorded_on_http_and_invisible_on_mcp`.

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

import asyncio
import dataclasses

import httpx
import pytest

pytest.importorskip("mcp", reason="requires the warden[mcp] extra")

# Only reachable once "mcp" itself imported cleanly -- importorskip above
# aborts the whole module before these lines run otherwise, and mcp_types is
# one of mcp==2.0.0's own pinned dependencies, so it is never absent when
# "mcp" is present. Same convention as test_mcp_surface.py's own post-skip
# imports.
from mcp.server import ServerRequestContext
from mcp_types._types import CallToolRequestParams
from mcp_types.version import LATEST_MODERN_VERSION

from warden.broker.adapters.base import ToolResult

VOLATILE = {"seq", "ts", "prev_hash", "hash"}


def _stripped(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in VOLATILE}


def _stripped_state(record: dict) -> dict:
    """`_stripped`, minus task_state.

    For the kinds where one door's call legitimately changes what the next
    door's call starts from -- see the module docstring's note on EXECUTED.
    Since P2·A that set includes the two post-execute faults: both settle
    their charge in a way that commits the class the call declared, because
    in both the adapter really did reach the source.
    """
    return {k: v for k, v in record.items() if k not in VOLATILE | {"task_state"}}


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
        # Every CASES entry is DENIED-shaped -- a TOOL error on MCP, not a
        # protocol error (see DENIED's own set in spine.py and render_call's
        # branch for it) -- so this is never expected to raise. No
        # try/except: a raise here is a genuine failure of this test's own
        # precondition, not a "legitimate alternate rendering" to swallow.
        mcp_result = call_tool(client, token, tool, args)

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
    call and leaves rows_charged_so_far untouched. Every field but
    task_state is asserted equal outright; task_state is asserted against
    the EXACT evolution a single, correctly-ordered taint tracker predicts,
    which is strictly more informative than raw equality would have been.

    This is also the ONE place the RENDERED content itself is compared, not
    only the audit record. EXECUTED is the one rendering where divergence
    directly changes what a model sees on a successful call -- app.py's
    JSON body carries `outcome.result.content` under "content"; mcp.py's
    `render_call` renders the SAME `outcome.result.content` as the tool
    result's text. Nothing upstream of rendering could ever produce a
    divergence there (both come from the same ToolResult the spine
    returned), which is exactly why only the RENDERING code path can
    introduce one -- and exactly why a record-only comparison, which is
    blind to rendering by construction, cannot see it. (MCP's
    `CallToolResult` carries no separate row count anywhere -- `render_call`
    never surfaces `outcome.result.rows` on any tool -- so there is nothing
    on that side to compare a row count against; HTTP's `rows` field is
    checked against the record it was built from instead.)
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
    assert http["task_state"] == {"data_classes_held": [], "rows_charged_so_far": 0}
    assert mcp["task_state"] == {
        "data_classes_held": ["public"],
        "rows_charged_so_far": 0,
    }

    body = response.json()
    assert body["content"] == "doc-body"
    assert body["content"] == result.content[0].text
    assert body["rows"] == 0


def test_both_surfaces_write_the_same_record_when_unauthenticated(tmp_path):
    """UNAUTHENTICATED, reached with a credential neither door can verify.

    Not folded into CASES above because the two doors build the request
    differently for a token of None (invoke() always sends an Authorization
    header -- even "Bearer None" -- while call_tool() omits the header
    entirely). A garbage token STRING, sent identically by both doors,
    sidesteps that difference: both land on the same
    `Spine._authenticate()` failure for the same reason.

    The raised MCPError's CODE is checked, not merely that SOME MCPError was
    raised -- `pytest.raises(MCPError)` alone cannot tell UNAUTHENTICATED
    apart from AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED (see
    test_both_surfaces_write_nothing_when_the_audit_log_is_unavailable),
    which raises the SAME exception type with a DIFFERENT code. mcp.py binds
    the two to `types.INVALID_REQUEST` and `types.INTERNAL_ERROR`
    respectively, exported as `UNAUTHENTICATED_CODE`/`FAULT_CODE`.
    """
    from mcp.shared.exceptions import MCPError

    from tests.warden.test_app import build_with_mcp, invoke
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer
    from warden.broker.mcp import UNAUTHENTICATED_CODE

    signer = Signer.generate()
    bogus = "not-a-jwt-at-all"
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        response = invoke(client, bogus, "read_document", {"doc_id": "a"})
        assert response.status_code == 401
        with pytest.raises(MCPError) as caught:
            call_tool(client, bogus, "read_document", {"doc_id": "a"})
        assert caught.value.code == UNAUTHENTICATED_CODE

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
    differs (a 502 / a tool error, instead of content).

    render_call's AFTER_EXECUTE branch RETURNS a `CallToolResult(is_error=
    True)` -- it does not raise -- so both renderings are available to
    compare, the same as every CASES entry above. This is the security-
    relevant rendering in the whole file: the "do not repeat this call"
    warning is what stops a model from re-sending an email (or any other
    already-executed action) that has no way to be un-sent, and it carries
    the seq of the specific durable-allow record EACH call wrote -- not a
    shared string, since the HTTP call and the MCP call each mint their OWN
    allow record with its OWN seq. So each rendering is checked against ITS
    OWN call's seq, not against each other directly -- a wrong seq on
    either side (or a rendering that drops it and falls back to a generic
    "nothing ran" message) fails this the same way a record disagreement
    would.
    """
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer
    from warden.broker.refusals import after_the_fact

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
        mcp_result = call_tool(client, token, "http_fetch", {"url": "http://x.internal/a"})
        assert mcp_result.is_error is True

        records = audit.records()
    assert len(records) == 2, records
    # task_state excluded for the reason the module docstring gives for
    # EXECUTED, which since P2·A applies to this kind too: the call's charge
    # is settled in a way that COMMITS the class it declared, because the
    # adapter really did reach the source. So the second door's pre-call
    # state is the first door's plus that class -- one task's state, shared
    # across both doors and correctly advancing, which is the property this
    # file exists to hold them to.
    assert _stripped_state(records[0]) == _stripped_state(records[1])
    assert records[0]["decision"] == "allow"
    assert records[0]["task_state"] == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }
    assert records[1]["task_state"] == {
        "data_classes_held": ["public"], "rows_charged_so_far": 0,
    }

    assert http.json()["message"] == after_the_fact(records[0]["seq"])
    assert mcp_result.content[0].text == after_the_fact(records[1]["seq"])


def test_both_surfaces_write_the_same_record_when_taint_rejects_the_read(tmp_path):
    """TAINT_REJECTED_AFTER_EXECUTE. Reached by handing the catalog an
    adapter whose execute() reports a negative row count -- taint.py's own
    guard against silently under-counting the row budget. Like
    EXECUTE_FAILED_AFTER_DURABLE_ALLOW, the allow record is durable before
    the taint update ever runs, so this too writes exactly one record per
    call -- and renders the same AFTER_EXECUTE warning, checked the same way
    (each call's own seq, not the two renderings against each other)."""
    from demo.mocks.seed_db import seed_customers
    from tests.support.catalog import demo_catalog
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer
    from warden.broker.refusals import after_the_fact

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
        mcp_result = call_tool(client, token, "read_document", {"doc_id": "a"})
        assert mcp_result.is_error is True

        records = audit.records()
    assert len(records) == 2, records
    # task_state excluded for the reason the module docstring gives for
    # EXECUTED, which since P2·A applies to this kind too: the call's charge
    # is settled in a way that COMMITS the class it declared, because the
    # adapter really did reach the source. So the second door's pre-call
    # state is the first door's plus that class -- one task's state, shared
    # across both doors and correctly advancing, which is the property this
    # file exists to hold them to.
    assert _stripped_state(records[0]) == _stripped_state(records[1])
    assert records[0]["decision"] == "allow"
    assert records[0]["task_state"] == {
        "data_classes_held": [], "rows_charged_so_far": 0,
    }
    assert records[1]["task_state"] == {
        "data_classes_held": ["public"], "rows_charged_so_far": 0,
    }

    assert http.json()["message"] == after_the_fact(records[0]["seq"])
    assert mcp_result.content[0].text == after_the_fact(records[1]["seq"])


# --- The two kinds that write ZERO records, for two different reasons ------


def test_both_surfaces_write_nothing_on_a_describe_backend_fault(tmp_path):
    """DESCRIBE_BACKEND_FAULT is the one branch of handle_tool_call that
    writes NO audit record at all -- spine.py's own comment: "no decision
    was avoided because of anything the caller did, so nothing is recorded
    against it." So the parity claim here is not "the two records agree"
    (there are none) -- it is that NEITHER door quietly writes one anyway,
    which a renderer with its own opinion about what "unaudited" means could
    still do. Unlike AFTER_EXECUTE, there is no durable record to name, so
    both renderings are the SAME static string (refusals.NOTHING_RAN) and
    are compared directly, not per-call."""
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.config.catalog import CatalogEntry, ToolCatalog
    from warden.broker.config.schema import ArgSpec, ToolSchema
    from warden.broker.identity import Signer
    from warden.broker.refusals import NOTHING_RAN

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

    assert http.json()["message"] == NOTHING_RAN
    assert result.content[0].text == NOTHING_RAN


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

    The raised MCPError's CODE is checked against `FAULT_CODE`
    (`types.INTERNAL_ERROR`) specifically -- `pytest.raises(MCPError)` alone
    cannot distinguish this from UNAUTHENTICATED (see
    test_both_surfaces_write_the_same_record_when_unauthenticated), which
    raises the same exception TYPE with `UNAUTHENTICATED_CODE`
    (`types.INVALID_REQUEST`) instead. A caller reading a raw JSON-RPC error
    code off the wire needs the two to actually differ, not merely both be
    "some MCPError".
    """
    from mcp.shared.exceptions import MCPError

    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer
    from warden.broker.mcp import FAULT_CODE

    signer = Signer.generate()
    token = "not-a-jwt-at-all" if unauthenticated else token_for(signer)

    with build_with_mcp(tmp_path, signer, payload) as (client, audit):

        def explode(**kwargs):
            raise OSError("disk full")

        audit.append = explode

        http = invoke(client, token, "read_document", {"doc_id": "a"})
        assert http.status_code == 503, f"{name}: {http.status_code}"
        assert http.json()["error"] == "audit_unavailable"

        with pytest.raises(MCPError) as caught:
            call_tool(client, token, "read_document", {"doc_id": "a"})
        assert caught.value.code == FAULT_CODE, f"{name}: {caught.value.code}"

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


def test_non_object_arguments_are_recorded_on_http_and_invisible_on_mcp(tmp_path):
    """A REAL divergence between the doors, reachable today by any caller --
    not the benign transport nicety `test_malformed_body_is_denied_over_
    http_only`'s unreachability note is about. That note is correct and
    airtight for `arguments: null` (which normalises to `{}`, never to the
    `None` MALFORMED_BODY_DENIED needs) -- but a well-formed JSON-RPC
    `tools/call` whose `arguments` is not an object AT ALL (a string, here)
    is a different mistake, and any MCP client can make it.

    HTTP: `_parse_args` rejects a non-dict `args` exactly like unparseable
    JSON -- `args=None` reaches the spine, which denies and AUDITS it as
    input.malformed (same Kind, same one-record shape, as the test above).

    MCP: the SDK validates `CallToolRequestParams.arguments: dict[str, Any]
    | None` with pydantic BEFORE any handler runs -- including
    `on_call_tool`. A non-dict value never reaches the spine at all:
    -32602 (INVALID_PARAMS), zero audit records. Not Kind.UNAUTHENTICATED's
    protocol-error shape either -- this is a request-shape rejection one
    layer further out than anything spine.py or mcp.py renders, and it is
    not the same latent gap mcp.py's own module docstring already names
    (the unaudited `Mcp-Param-*` header mismatch under
    `_is_internal_schema_lookup`) -- that one is about HEADERS disagreeing
    with a well-formed body; this one is the BODY itself being a shape the
    spine can never see.

    So: the same caller mistake is recorded on one door and leaves no trace
    on the other -- exactly the divergence class this file exists to
    surface. Fixing it would require routing the SDK's own pre-dispatch
    rejection into the spine via `ServerMiddleware`, which is out of scope
    for this task; pinning it here, so it is a documented fact rather than
    folklore the next person has to rediscover, is the deliverable.
    """
    from mcp_types import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY

    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        # HTTP: a non-dict "args" is audited as a denied, recorded attempt --
        # the same one-record shape test_malformed_body_is_denied_over_http_
        # only pins for an unparseable body.
        http = client.post(
            "/v1/tools/read_document/invoke",
            json={"args": "not-a-dict"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert http.status_code == 403
        assert http.json()["rule"] == "input.malformed"
        after_http = audit.records()
        assert len(after_http) == 1
        assert after_http[0]["rule"] == "input.malformed"

        # MCP: the SAME caller mistake, sent as a well-formed JSON-RPC
        # tools/call with a non-dict `arguments` -- never reaches the spine.
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_document",
                "arguments": "not-a-dict",
                "_meta": {
                    PROTOCOL_VERSION_META_KEY: LATEST_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META_KEY: {},
                },
            },
        }
        headers = {
            "MCP-Protocol-Version": LATEST_MODERN_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "read_document",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
        }
        mcp_response = client.post("/mcp", json=body, headers=headers)
        assert mcp_response.status_code == 400
        assert mcp_response.json()["error"]["code"] == -32602

        # The divergence, stated as a fact: HTTP recorded the attempt: MCP
        # added nothing at all.
        assert audit.records() == after_http


def test_explicit_null_args_is_denied_on_http_and_can_execute_on_mcp(tmp_path):
    """A SECOND real divergence, next to the non-object-arguments one above
    -- undocumented until now, and found by driving the case the module
    docstring used to wave off as "benign".

    HTTP: `{"args": null}` is a well-formed JSON body carrying an EXPLICIT
    null, not an absent key -- `app.py`'s `_parse_args` does
    `body.get("args", {})`, which returns the literal `None` here because
    the key IS present, not the `{}` default. `args=None` reaches the spine
    and is denied UNCONDITIONALLY as `Kind.MALFORMED_BODY_DENIED` --
    `input.malformed` -- without ever consulting the tool's schema.

    MCP: `"arguments": null` in a well-formed `tools/call` normalises to
    `{}` inside `on_call_tool`, BEFORE the spine is ever called -- the same
    normalisation an ABSENT `arguments` gets. The call then proceeds to the
    spine like any other, and is judged on the tool's ACTUAL schema.

    For a tool that requires at least one argument (every tool in the
    shipped demo catalog), that schema check fails too, landing on
    `Kind.SCHEMA_INVALID_DENIED` -- which happens to share spine.py's same
    `MALFORMED = "input.malformed"` rule string and the same `{}` digest as
    `MALFORMED_BODY_DENIED`, so the two doors' audit records come out
    byte-identical despite being different `Kind`s underneath. That
    coincidence is what let the parity claim look true for this input.

    For a tool whose schema has NO required arguments -- legitimate
    catalog configuration, just absent from the shipped demo -- MCP's
    normalised `{}` PASSES that schema, so the call proceeds all the way to
    `describe()`/`decide()`/`execute()`: ALLOWED and EXECUTED. HTTP still
    denies the identical logical request outright, because
    `MALFORMED_BODY_DENIED` never looks at the schema at all. That is the
    divergence this test pins: not a wording nicety, but one door executing
    a tool call the other door refuses to even evaluate.
    """
    from mcp_types import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY

    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.adapters.base import ToolResult, ToolTarget
    from warden.broker.config.catalog import CatalogEntry, ToolCatalog
    from warden.broker.config.schema import ToolSchema
    from warden.broker.identity import Signer

    class NoArgsAdapter:
        target_kind = "doc"
        # Required by the Adapter protocol since P2·A: the spine charges a
        # call's declared class before execute() runs, so it is read from the
        # adapter rather than from the result. A double without it makes the
        # catalog raise AttributeError on every call to this tool.
        data_class = "public"

        def describe(self, args):
            return ToolTarget(kind="doc", path="/x")

        def execute(self, args):
            return ToolResult(content="ok", data_class="public")

    # A schema with NO required arguments at all -- not `{"doc_id": ...}`
    # like the demo catalog's own read_document, which is exactly what
    # makes this reachable: `catalog.validate(tool, {})` succeeds here,
    # where it fails for every shipped tool.
    catalog = ToolCatalog({
        "no_required_args": CatalogEntry(
            kind="docstore",
            target_kind="doc",
            schema=ToolSchema(args={}),
            adapter=NoArgsAdapter(),
        )
    })

    signer = Signer.generate()
    token = token_for(signer, allowed_tools=["no_required_args"])
    with build_with_mcp(
        tmp_path, signer, {"allow": True, "deny_reasons": []}, catalog=catalog
    ) as (client, audit):
        # HTTP: explicit null args, denied unconditionally -- the schema is
        # never consulted for MALFORMED_BODY_DENIED.
        http = client.post(
            "/v1/tools/no_required_args/invoke",
            json={"args": None},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert http.status_code == 403
        assert http.json()["rule"] == "input.malformed"

        # MCP: explicit null arguments, normalised to {} before the spine
        # ever sees it, and {} satisfies this tool's (empty) schema.
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "no_required_args",
                "arguments": None,
                "_meta": {
                    PROTOCOL_VERSION_META_KEY: LATEST_MODERN_VERSION,
                    CLIENT_CAPABILITIES_META_KEY: {},
                },
            },
        }
        headers = {
            "MCP-Protocol-Version": LATEST_MODERN_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "no_required_args",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
        }
        mcp_response = client.post("/mcp", json=body, headers=headers)
        assert mcp_response.status_code == 200
        result = mcp_response.json()["result"]
        assert result["isError"] is False
        assert result["content"][0]["text"] == "ok"

        # The divergence, stated as a fact: one denial, one execution, for
        # the identical logical request.
        records = audit.records()
    assert [r["decision"] for r in records] == ["deny", "allow"]
    assert records[0]["rule"] == "input.malformed"


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

    The HTTP-route check compares the full SET of `/v1/`-prefixed routes
    against `{"/v1/tools/{tool}/invoke"}`, not membership of one literal
    string that happens never to match anything -- `"/v1/tools"` (no
    trailing segment) is not a route this app has ever mounted, under any
    version of app.py, so a membership check against exactly that string
    would pass whether or not a NEW listing route showed up beside the
    invoke route. Comparing the set catches any addition, not only that one
    guessed spelling.
    """
    from tests.warden.test_app import build_with_mcp, token_for
    from tests.warden.test_mcp_surface import list_tools
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        v1_routes = {
            route.path for route in client.app.routes
            if getattr(route, "path", "").startswith("/v1/")
        }
        assert v1_routes == {"/v1/tools/{tool}/invoke"}, v1_routes
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
        after_http = spine.task_state("4711")["rows_charged_so_far"]
        call_tool(client, token, "query_customers", {"filter": "id=8812"})
        after_mcp = spine.task_state("4711")["rows_charged_so_far"]
        assert after_http == 1
        assert after_mcp == 2


# --- The concurrency mirror --------------------------------------------
#
# `call_tool()` reaches the app through the SDK's own `Client`, bridged onto
# the app's event loop via `anyio`'s `BlockingPortal.call()` --  which BLOCKS
# the calling thread for the whole round trip. Two `tg.start_soon(one)`
# tasks that each call it therefore never truly race: the first has to
# finish entirely before the second's request is even sent. Measured by
# instrumenting a deliberately-slow OPA handler with entry/exit timestamps,
# under both the plain `call_tool()` form AND a genuinely-concurrent
# `asyncio.gather` submitted through the portal in one shot: zero overlap
# either way, for the CURRENT (correct) code -- because `on_call_tool` has
# no `await` between reading `params.arguments` and calling the fully
# synchronous spine, so whichever task starts running first runs to
# completion, uninterruptible, before the scheduler ever looks at the other
# one. So this earlier finding was real, but the conclusion drawn from it
# the first time round was not: "no overlap, ever" was read as "the test
# cannot be made to interleave", when it actually only showed "the current,
# correct code gives a genuine race no opening" -- which says nothing about
# whether the TEST would notice if that stopped being true.
#
# The fix is to stop going through the portal at all. `on_call_tool` --
# reached the same way test_the_registered_handlers_are_coroutine_functions
# below reaches it, `server.app.get_request_handler("tools/call").handler`
# -- is a plain async closure over `spine`, with no session or transport
# state of its own. Calling it directly via `asyncio.gather`, on whatever
# loop this test itself runs on, needs no portal and no blocking bridge, so
# TWO genuinely concurrent `asyncio.Task`s reach it. Proven by mutation, not
# assumed: with `Spine.handle_tool_call` made `async def` and a real
# `await anyio.sleep(0.05)` inserted between the taint snapshot and the
# durable write (mirroring test_app.py's own race exactly, and requiring the
# two call sites in app.py/mcp.py to `await` it) --
#   * test_app.py's OWN concurrency test fails: 200/200, budget bypassed.
#   * the OLD (call_tool()-through-the-portal) form of this test: still
#     PASSED -- it cannot see the regression, confirming the finding above.
#   * the NEW (direct-handler, asyncio.gather) form below: FAILS --
#     ['allow', 'allow'], the exact bypass. Reverted after confirming.


def _call_tool_handler(client):
    """The registered `on_call_tool` closure itself -- not a wrapper, not a
    copy. Same accessor `test_the_registered_handlers_are_coroutine_functions`
    uses; shared here because calling it directly (bypassing the SDK
    `Client` and the blocking portal bridge) is what makes genuine
    concurrent dispatch possible at all -- see the section comment above.
    """
    return client.app.state.mcp_session_manager.app.get_request_handler(
        "tools/call"
    ).handler


@dataclasses.dataclass
class _FakeRequest:
    headers: dict


def _call_context(token: str | None) -> ServerRequestContext:
    """Just enough of a `ServerRequestContext` for `on_call_tool`'s own
    reads (`_credential()`, via `_headers()`) -- the same construction
    test_mcp_surface.py's `test_the_inline_lookup_is_answered_from_the_
    catalog_not_with_an_empty_list` uses to drive a handler directly,
    without a session or a real transport underneath it."""
    return ServerRequestContext(
        session=None,
        lifespan_context=None,
        protocol_version=LATEST_MODERN_VERSION,
        method="tools/call",
        request=_FakeRequest(
            headers={} if token is None else {"authorization": f"Bearer {token}"}
        ),
    )


async def test_concurrent_mcp_calls_for_one_task_do_not_exceed_the_row_bound(tmp_path):
    """Two `tools/call` requests for ONE task_id, dispatched as two genuine
    `asyncio.Task`s on one event loop -- not two sequential round trips that
    happen to land on the same conclusion. See the section comment above for
    what was measured and what closes the gap.
    """
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)

    def opa(request):
        import json as _json

        state = _json.loads(request.content)["input"]["task_state"]
        allow = state["rows_charged_so_far"] < 1
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
        handler = _call_tool_handler(client)
        params = CallToolRequestParams(
            name="query_customers", arguments={"filter": "id=8812"}
        )

        results = await asyncio.gather(
            handler(_call_context(token), params),
            handler(_call_context(token), params),
        )

    assert sorted(r.is_error for r in results) == [False, True]
    decisions = [r["decision"] for r in audit.records()]
    assert sorted(decisions) == ["allow", "deny"]


@pytest.mark.parametrize("method", ["tools/call", "tools/list"])
def test_the_registered_handlers_are_coroutine_functions(tmp_path, method):
    """A sync handler runs on a worker thread, which puts the snapshot and
    the read it authorises on different threads with nothing between them.

    Both handlers, not just `on_call_tool`: mcp.py's own module docstring
    states the invariant for "Both handlers" together, and `on_list_tools`
    calls `spine.list_tools` the same inline, no-await way -- a sync
    `on_list_tools` would go unnoticed by a test that only ever checked the
    other one.
    """
    import inspect

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        _,
    ):
        server = client.app.state.mcp_session_manager
        entry = server.app.get_request_handler(method)
        assert entry is not None, f"could not reach the registered {method} handler"
        assert inspect.iscoroutinefunction(entry.handler), method
