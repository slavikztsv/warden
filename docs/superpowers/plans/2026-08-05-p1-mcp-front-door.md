# P1 — MCP Front Door Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `warden` a third front door — an MCP surface — so an agent whose code you do not own can call brokered tools, without any surface being able to disagree with another about what a call was.

**Architecture:** Extract `app.py`'s decision logic into a transport-free, fully synchronous `Spine` that returns an `Outcome` value. `app.py` becomes an HTTP rendering of `Outcome`; a new `warden/broker/mcp.py` becomes an MCP rendering of the same `Outcome`, mounted in the same process and disabled by default. A `warden mcp` subcommand forwards stdio to that surface and holds no authority.

**Tech Stack:** Python 3.11+, FastAPI 0.141.1, `mcp==2.0.0` (optional extra), OPA/Rego, pytest.

**Spec:** [docs/superpowers/specs/2026-08-05-p1-mcp-front-door-design.md](../specs/2026-08-05-p1-mcp-front-door-design.md). The spec is authoritative; this plan is how to build it.

## Global Constraints

Every task's requirements implicitly include this section. Each line is a red CI run if violated.

- **No `.py`, `.rego`, `.toml` or `.json` file under `warden/` may contain the substrings:** `4711`, `8812`, `attacker.example`, `docstore.internal`, `support-triage`, `triage-bot`, `refund`, `customers`, `demo/`. Enforced by `tests/test_seam.py`. Note `customers` is a bare substring — an example table named "customers" fails, and so does the word in a docstring.
- **No `.py` under `warden/broker/` may contain:** `read_document`, `query_customers`, `http_fetch`, `send_email`. Enforced by `tests/warden/test_seam_precursor.py`. MCP docstrings must not illustrate `tools/list` with the demo's tool names.
- **No file under `warden/` or `demo/` may contain:** `python -m cli.`, `python -m agent.`, `python -m broker`, `./scripts/demo.sh`, `broker/backends.py`, `docker-compose.yml`, `cli/warden.py`. `python -m broker` is a **prefix** match, so `python -m broker.mcp` fails; `python -m warden.broker` is safe. Enforced by `tests/test_docs_are_current.py`.
- **A mention of the policy file must be written `warden/policies/authz.rego` or `/policies/authz.rego`**, never bare. Enforced by the same test, over docs *and* every `.py` under `warden/` and `demo/`.
- **New modules go inside the already-enumerated `warden.broker` package** — `warden/broker/spine.py`, `warden/broker/mcp.py`. A new *subpackage* would have to be added to `warden/pyproject.toml`'s explicit `packages` list or it fails at test collection.
- **`mcp` is an optional extra**, never a hard dependency of `warden`. `tests/warden/test_entry_points.py` reads `project("warden")["dependencies"]`.
- **Tests live outside `warden/`** and may freely use the demo's tool names — the existing suite does.
- **Run the full suite with** `.venv/bin/pytest -q`. The 21 `test_golden_decisions.py` errors are pre-existing and environmental (no OPA binary); ignore them unless your change adds to the count.

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `warden/broker/spine.py` | `Kind`, `Outcome`, `ListOutcome`, `Spine`. The whole decision sequence as a value. No transport knowledge. |
| `warden/broker/schema_json.py` | `ArgSpec`/`ToolSchema` → JSON Schema 2020-12. One function, no state. |
| `warden/broker/mcp.py` | The MCP surface: builds the low-level `Server`, renders `Outcome`, mounts into the app. Lazily imported. |
| `warden/cli/mcp_shim.py` | The stdio forwarder. Holds a token file and an upstream client; no policy, no catalog. |
| `tests/warden/test_spine.py` | Outcome variants, rendering idempotence, totality. |
| `tests/warden/test_schema_json.py` | Generator mapping and the agreement property test. |
| `tests/warden/test_mcp_surface.py` | Mount, auth, `tools/call`, `tools/list`, era parity, disabled-by-default. |
| `tests/warden/test_surface_parity.py` | Both surfaces against one app and one audit log. |
| `tests/warden/test_mcp_shim.py` | The six shim hardening rules. |

**Modified:** `warden/broker/app.py` (reduced to routing + rendering), `warden/broker/config/loader.py` (`[mcp]`), `warden/broker/config/catalog.py` (`_TOOL_KEYS`, `description`, `title`), `warden/broker/config/check.py` (MCP checks), `warden/broker/__main__.py` (wire `mcp=`), `warden/cli/main.py` (`warden mcp`), `warden/cli/replay.py` (`tool_list` rendering + config front door), `warden/pyproject.toml` (extra), `tests/warden/test_app.py` (clock injection).

---

### Task 1: Pin the deny-path audit failure

The one branch P1 rewrites across five call sites with zero coverage. This is a **characterization test** — it pins behaviour that already works, so the refactor cannot change it silently. It must be written and committed before any refactoring.

**Files:**
- Test: `tests/warden/test_app.py` (append)

**Interfaces:**
- Consumes: existing `build()`, `token_for()`, `invoke()` helpers in that file.
- Produces: nothing later tasks import.

- [ ] **Step 1: Write the test**

Append to `tests/warden/test_app.py`:

```python
def test_audit_write_failure_on_a_deny_is_reported_not_hidden(tmp_path, signer):
    """The deny path's own 503. _write_deny_record catches OSError and returns
    audit_unavailable, and every one of the five deny call sites funnels
    through it -- so a log that cannot be written must not become a quiet 403
    that looks like an ordinary refusal."""
    client, audit = build(
        tmp_path, signer, {"allow": False, "deny_reasons": ["rows.bounded"]}
    )

    def explode(**kwargs):
        raise OSError("disk full")

    audit.append = explode
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    assert response.status_code == 503
    assert response.json()["error"] == "audit_unavailable"
    assert "disk full" in response.json()["message"]
```

- [ ] **Step 2: Run it — expect PASS**

Run: `.venv/bin/pytest tests/warden/test_app.py::test_audit_write_failure_on_a_deny_is_reported_not_hidden -v`
Expected: **PASS.** This is deliberate — the behaviour exists, the coverage did not. A failure here means `_write_deny_record` does not do what `app.py:322` claims, which is a finding to report before continuing.

- [ ] **Step 3: Commit**

```bash
git add tests/warden/test_app.py
git commit -m "test: pin the deny path's audit-unavailable branch before refactoring it"
```

---

### Task 2: `X-Warden-Rule` on tool-API denials

`README.md:283`'s integration diagram already tells readers the tool API sets this header. Only `proxy.py` does. Make the documented claim true.

**Files:**
- Modify: `warden/broker/app.py` (the `_deny` helper)
- Test: `tests/warden/test_app.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: a `403` response carrying `X-Warden-Rule: <rule>`. Task 4 preserves it; Task 14 asserts parity on it.

- [ ] **Step 1: Write the failing test**

```python
def test_a_denial_names_its_rule_in_a_header(tmp_path, signer):
    """The README's integration diagram tells readers a deny returns 403 with
    the rule in X-Warden-Rule. proxy.py does this; the tool API did not."""
    client, _ = build(
        tmp_path, signer, {"allow": False, "deny_reasons": ["rows.bounded"]}
    )
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    assert response.status_code == 403
    assert response.headers["X-Warden-Rule"] == "rows.bounded"
```

- [ ] **Step 2: Run it — expect FAIL**

Run: `.venv/bin/pytest tests/warden/test_app.py::test_a_denial_names_its_rule_in_a_header -v`
Expected: FAIL with `KeyError: 'x-warden-rule'`.

- [ ] **Step 3: Add the header**

In `warden/broker/app.py`, in `_deny`, replace the returned `JSONResponse` with:

```python
    return JSONResponse(
        {
            "error": "policy_denied",
            "rule": rule,
            "message": f"Denied by policy rule {rule}.",
        },
        status_code=403,
        # The rule, where a proxy-aware client can read it without parsing a
        # body -- the same header broker/proxy.py sets on its own refusals.
        headers={"X-Warden-Rule": rule},
    )
```

- [ ] **Step 4: Run the file**

Run: `.venv/bin/pytest tests/warden/test_app.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add warden/broker/app.py tests/warden/test_app.py
git commit -m "feat: name the rule in X-Warden-Rule on the tool API, as the diagram already claims"
```

---

### Task 3: Inject the clock

Three tests patch `warden.broker.app.now` by module-global assignment. Once the decision logic moves to `spine.py`, that patch point stops covering it — and would silently stop covering the MCP surface too. One injected clock covers both.

**Files:**
- Modify: `warden/broker/app.py` (`create_app` signature)
- Modify: `tests/warden/test_app.py` (three tests + the `build` helper)

**Interfaces:**
- Consumes: nothing.
- Produces: `create_app(..., clock: Callable[[], int] | None = None)`. Task 4 passes it into `Spine`. Tests use a mutable `Clock` object.

- [ ] **Step 1: Add the parameter**

In `warden/broker/app.py`, change `create_app`'s signature and capture the clock:

```python
def create_app(
    *,
    verifier: Verifier,
    pdp: PolicyDecisionPoint,
    taint: TaintTracker,
    audit: AuditLog,
    catalog: ToolCatalog,
    policy_digest: str,
    clock: "Callable[[], int] | None" = None,
) -> FastAPI:
    # Injected rather than read from this module's globals at call time.
    # Patching a module global covers exactly the module that reads it, and
    # the decision sequence is about to be shared with a second surface that
    # would not read this one. One clock, both surfaces, one patch point.
    clock = clock or now
```

Add `from collections.abc import Callable` to the imports, and replace the body's `now=now()` in `verifier.verify(...)` with `now=clock()`.

- [ ] **Step 2: Give the tests a controllable clock**

In `tests/warden/test_app.py`, add near the top (after the imports):

```python
class Clock:
    """A clock the tests can move. Replaces patching app_module.now by
    assignment, which only ever covered the module that read that global."""

    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value
```

Change `build` to accept and forward it:

```python
def build(tmp_path, signer, opa_payload, backend_handler=None, clock=None):
```

and add `clock=clock,` to the `create_app(...)` call inside it. Do the same for `app_with_catalog`: add `clock=None` to its signature and `clock=clock,` to its `create_app(...)` call.

- [ ] **Step 3: Convert the three tests**

There are **three patch sites, spanning four test functions**, because one of
them is inside a shared helper:

| Site | Holder | Covers |
|---|---|---|
| ~line 155 | `test_expired_token_is_rejected` | itself |
| ~line 717 | `test_expired_token_never_reaches_pdp_or_backend` | itself |
| ~line 904 | the helper `_unauthenticated_requests` | `test_every_unauthenticated_call_leaves_an_audit_record` and `test_unauthenticated_records_chain_with_real_decisions` |

`test_concurrent_reads_for_the_same_task_do_not_exceed_the_row_bound` does
**not** touch the clock — an earlier draft of this plan said it did, from a
script that walked back to the nearest `def test` and stepped over the
non-test helper in between. Leave that test alone.

Each site currently looks like:

```python
    import warden.broker.app as app_module
    original = app_module.now
    app_module.now = lambda: 10**12
    try:
        ...body...
    finally:
        app_module.now = original
```

Becomes — pass `clock=clock` to the `build(...)` call in that test, then:

```python
    clock.value = 10**12
    ...body, de-indented out of the try/finally...
```

with `clock = Clock()` constructed before `build(...)`. There is no `finally` to restore: the clock is per-test.

- [ ] **Step 4: Run the file**

Run: `.venv/bin/pytest tests/warden/test_app.py -q`
Expected: all pass, including the three converted tests.

- [ ] **Step 5: Commit**

```bash
git add warden/broker/app.py tests/warden/test_app.py
git commit -m "refactor: inject the clock, so one patch point covers every surface"
```

---

### Task 4: Extract the spine

The heart of P1. Behaviour-neutral: the existing 34 tests in `test_app.py` are the acceptance criterion and must pass unchanged.

**Files:**
- Create: `warden/broker/spine.py`
- Modify: `warden/broker/app.py`
- Test: `tests/warden/test_spine.py`

**Interfaces:**
- Consumes: `create_app(..., clock=)` from Task 3; the `X-Warden-Rule` header from Task 2.
- Produces:
  - `Kind` — a `str, Enum` with members `EXECUTED`, `LISTED`, `POLICY_DENIED`, `UNKNOWN_TOOL_DENIED`, `MALFORMED_BODY_DENIED`, `SCHEMA_INVALID_DENIED`, `DESCRIBE_CLIENT_ERROR_DENIED`, `DESCRIBE_BACKEND_FAULT`, `UNAUTHENTICATED`, `AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED`, `AUDIT_UNAVAILABLE_ON_ALLOW`, `AUDIT_UNAVAILABLE_ON_DENY`, `EXECUTE_FAILED_AFTER_DURABLE_ALLOW`, `TAINT_REJECTED_AFTER_EXECUTE`.
  - `DENIED`, `AUDIT_UNAVAILABLE`, `FAULT` — `frozenset[Kind]` groupings.
  - `Outcome(kind, rule="", result=None, message="", audit_seq=None)` — frozen dataclass.
  - `ListOutcome(kind, tools=(), message="")` — frozen dataclass.
  - `Spine(*, verifier, pdp, taint, audit, catalog, policy_digest, clock)` with `handle_tool_call(credential: str | None, tool: str, args: dict | None) -> Outcome` and `list_tools(credential: str | None) -> ListOutcome`.
  - `create_app` gains `spine` on the returned app as `app.state.spine`, so Task 11 can reach it.

> **On `PdpUnavailableDenied`:** the spec's table lists it as variant 3 and notes it is a sub-case. It is `POLICY_DENIED` carrying `rule="pdp.unavailable"` — the code path and the rendering are identical, and a separate `Kind` would mean inspecting a rule string to pick it. Thirteen `Kind` members cover the fourteen rows. `test_a_pdp_outage_denies_rather_than_faulting` (Task 4, step 6) pins that it stays a denial.

- [ ] **Step 1: Write `warden/broker/spine.py`**

```python
"""The decision sequence, as a value rather than a response.

verify -> snapshot -> validate -> decide -> record -> execute. Nothing here
knows about HTTP or any wire protocol: it returns an Outcome, and a surface
renders it. That is what stops two front doors onto one broker from
disagreeing about what a call was.

The sequence is SYNCHRONOUS on purpose, and it is a security property rather
than a style choice. Between taking the task-state snapshot and recording
what a call read, nothing may suspend -- two calls for one task that
interleave there both read the same starting budget and both pass. Inside an
async handler that invariant is held by hand, and a comment is the only thing
holding it. A function containing no `await` cannot break it at all.

Every side effect lives here: the audit write, the execution, the taint
update. Rendering an Outcome is therefore pure and repeatable. A renderer
that applied the taint update would let two surfaces apply it twice, or in a
different order relative to the audit write, and a budget that drifts does so
silently.

Authentication is inside this boundary too, which is the whole reason the
entry point takes a raw credential rather than a verified token. A call
arriving without authority is what a probe looks like, and refusing it
without recording it makes a probe indistinguishable from a run that never
happened. Leaving that branch to each surface would give the second surface
its own copy to drift.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from warden.broker.adapters.base import ToolResult, ToolTarget, UnknownTool
from warden.broker.identity import TokenInvalid

UNAUTHENTICATED = "unauthenticated"
MALFORMED = "input.malformed"
CAPABILITY = "tools.allowed"


class Kind(str, Enum):
    EXECUTED = "executed"
    LISTED = "listed"
    POLICY_DENIED = "policy_denied"
    UNKNOWN_TOOL_DENIED = "unknown_tool_denied"
    MALFORMED_BODY_DENIED = "malformed_body_denied"
    SCHEMA_INVALID_DENIED = "schema_invalid_denied"
    DESCRIBE_CLIENT_ERROR_DENIED = "describe_client_error_denied"
    DESCRIBE_BACKEND_FAULT = "describe_backend_fault"
    UNAUTHENTICATED = "unauthenticated"
    AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED = "audit_unavailable_on_unauthenticated"
    AUDIT_UNAVAILABLE_ON_ALLOW = "audit_unavailable_on_allow"
    AUDIT_UNAVAILABLE_ON_DENY = "audit_unavailable_on_deny"
    EXECUTE_FAILED_AFTER_DURABLE_ALLOW = "execute_failed_after_durable_allow"
    TAINT_REJECTED_AFTER_EXECUTE = "taint_rejected_after_execute"


DENIED = frozenset({
    Kind.POLICY_DENIED,
    Kind.UNKNOWN_TOOL_DENIED,
    Kind.MALFORMED_BODY_DENIED,
    Kind.SCHEMA_INVALID_DENIED,
    Kind.DESCRIBE_CLIENT_ERROR_DENIED,
})

AUDIT_UNAVAILABLE = frozenset({
    Kind.AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED,
    Kind.AUDIT_UNAVAILABLE_ON_ALLOW,
    Kind.AUDIT_UNAVAILABLE_ON_DENY,
})

# Three faults with three different audit consequences, kept apart on
# purpose. DESCRIBE_BACKEND_FAULT wrote nothing at all; the other two each
# left exactly one durable allow record for an action that may have already
# happened. A surface that collapses them cannot tell a caller which.
FAULT = frozenset({
    Kind.DESCRIBE_BACKEND_FAULT,
    Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW,
    Kind.TAINT_REJECTED_AFTER_EXECUTE,
})

EMPTY_STATE = {"data_classes_held": [], "rows_returned_so_far": 0}


def args_digest(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Outcome:
    kind: Kind
    rule: str = ""
    result: ToolResult | None = None
    message: str = ""
    # The seq of the durable allow record, on the two variants that fire
    # after one was written. A caller that must not retry needs a handle on
    # the thing that already happened.
    audit_seq: int | None = None


@dataclass(frozen=True)
class ListOutcome:
    kind: Kind
    tools: tuple[str, ...] = ()
    message: str = ""


class Spine:
    def __init__(
        self,
        *,
        verifier,
        pdp,
        taint,
        audit,
        catalog,
        policy_digest: str,
        clock: Callable[[], int],
    ) -> None:
        self._verifier = verifier
        self._pdp = pdp
        self._taint = taint
        self._audit = audit
        self._catalog = catalog
        self._digest = policy_digest
        self._clock = clock

    def _authenticate(self, credential: str | None):
        if credential is None:
            return None, "Bearer token required."
        try:
            return self._verifier.verify(credential, now=self._clock()), ""
        except TokenInvalid as exc:
            return None, str(exc)

    def handle_tool_call(
        self, credential: str | None, tool: str, args: dict | None
    ) -> Outcome:
        token, message = self._authenticate(credential)
        if token is None:
            return self._refuse(
                {"type": "tool_call", "tool": tool}, message, Outcome
            )

        # After every suspension point the caller could have had, and before
        # anything reads it. One snapshot feeds the policy input, the audit
        # record and every deny record; it is never re-read.
        state = self._taint.snapshot(token.task_id)

        if args is None:
            # A body that did not parse. Audited against the literal empty
            # dict, because there are no arguments to digest.
            return self._deny(
                token, tool, {}, ToolTarget(kind="malformed"), state,
                MALFORMED, Kind.MALFORMED_BODY_DENIED,
            )

        if not self._catalog.validate(tool, args):
            return self._deny(
                token, tool, args, ToolTarget(kind="malformed"), state,
                MALFORMED, Kind.SCHEMA_INVALID_DENIED,
            )

        try:
            target = self._catalog.describe(tool, args)
        except UnknownTool:
            # Order matters: UnknownTool is a plain Exception subclass, so
            # this clause must stay above both of the ones below.
            return self._deny(
                token, tool, args, ToolTarget(kind="unknown"), state,
                CAPABILITY, Kind.UNKNOWN_TOOL_DENIED,
            )
        except (ValueError, KeyError, TypeError, IndexError):
            # Client-caused failures the schema did not catch. The tuple is
            # exactly these four and was widened on purpose: KeyError is not
            # a ValueError, and sending it to the branch below produced a
            # fault with no record -- an agent probing with no trace.
            return self._deny(
                token, tool, args, ToolTarget(kind="malformed"), state,
                MALFORMED, Kind.DESCRIBE_CLIENT_ERROR_DENIED,
            )
        except Exception as exc:
            # A server bug, not the agent's doing. No decision was avoided
            # because of anything the caller did, so nothing is recorded
            # against it.
            return Outcome(kind=Kind.DESCRIBE_BACKEND_FAULT, message=str(exc))

        decision = self._pdp.decide({
            "principal": {
                "agent_id": token.agent_id,
                "task_id": token.task_id,
                "purpose": token.purpose,
                "allowed_tools": list(token.allowed_tools),
                "counterparties": list(token.counterparties),
            },
            "action": {
                "type": "tool_call",
                "tool": tool,
                "args_digest": args_digest(args),
            },
            "target": target.as_dict(),
            "task_state": state,
        })

        if not decision.allow:
            return self._deny(
                token, tool, args, target, state, decision.rule, Kind.POLICY_DENIED
            )

        try:
            record = self._append(
                token, tool, args_digest(args), target, state, "allow", decision.rule
            )
        except OSError as exc:
            # If it cannot be logged, it cannot be done. execute() must not
            # run below.
            return Outcome(kind=Kind.AUDIT_UNAVAILABLE_ON_ALLOW, message=str(exc))

        try:
            result = self._catalog.execute(tool, args)
        except Exception as exc:
            # Deliberately broad. The allow above is durable, so nothing may
            # escape this call site or the log asserts an authorised action
            # while a caller sees a bare crash. No second record is written:
            # the allow stands as the account of what was authorised.
            return Outcome(
                kind=Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW,
                message=str(exc),
                audit_seq=record["seq"],
            )

        try:
            self._taint.record_read(
                token.task_id, data_class=result.data_class, rows=result.rows
            )
        except ValueError as exc:
            # taint.py rejects a negative row count rather than silently
            # under-counting a budget. Honour that: report it, leave the
            # state untouched, and do not write a second record.
            return Outcome(
                kind=Kind.TAINT_REJECTED_AFTER_EXECUTE,
                message=str(exc),
                audit_seq=record["seq"],
            )

        return Outcome(
            kind=Kind.EXECUTED,
            rule=decision.rule,
            result=result,
            audit_seq=record["seq"],
        )

    def list_tools(self, credential: str | None) -> ListOutcome:
        """What this token may call. Usability, never enforcement.

        The catalog is the deployment's map of its own internal systems, so
        an unauthenticated listing is refused and recorded like any other
        call arriving without authority. An authenticated one records
        nothing: no action was taken, and logging every client's periodic
        refresh would bury the records that matter.
        """
        token, message = self._authenticate(credential)
        if token is None:
            return self._refuse({"type": "tool_list"}, message, ListOutcome)
        granted = frozenset(token.allowed_tools) & self._catalog.names()
        return ListOutcome(kind=Kind.LISTED, tools=tuple(sorted(granted)))

    def _refuse(self, action: dict, message: str, factory):
        """Records a call that carried no usable authority, then refuses it.

        There is no token, so there is no principal: the fields carry the
        same sentinels broker/proxy.py's own refusal record uses, which the
        replay renderer already knows. The request body is deliberately
        never read -- nothing an unauthenticated caller claims is
        trustworthy, and parsing it would only add a failure mode.
        """
        try:
            self._audit.append(
                task_id="-",
                agent_id=UNAUTHENTICATED,
                purpose="-",
                action=action,
                target=ToolTarget(kind="unknown").as_dict(),
                args_digest="sha256:none",
                decision="deny",
                rule=UNAUTHENTICATED,
                task_state=EMPTY_STATE,
                policy_bundle_digest=self._digest,
            )
        except OSError as exc:
            return factory(
                kind=Kind.AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED, message=str(exc)
            )
        return factory(kind=Kind.UNAUTHENTICATED, message=message)

    def _deny(self, token, tool, args, target, state, rule, kind) -> Outcome:
        try:
            self._append(token, tool, args_digest(args), target, state, "deny", rule)
        except OSError as exc:
            return Outcome(kind=Kind.AUDIT_UNAVAILABLE_ON_DENY, message=str(exc))
        return Outcome(kind=kind, rule=rule, message=f"Denied by policy rule {rule}.")

    def _append(self, token, tool, digest, target, state, decision, rule) -> dict:
        # The audited action deliberately carries no args_digest of its own:
        # that field is the policy input's, and building one dict for both
        # would change whichever of the two it was not written for.
        return self._audit.append(
            task_id=token.task_id,
            agent_id=token.agent_id,
            purpose=token.purpose,
            action={"type": "tool_call", "tool": tool},
            target=target.as_dict(),
            args_digest=digest,
            decision=decision,
            rule=rule,
            task_state=state,
            policy_bundle_digest=self._digest,
        )
```

- [ ] **Step 2: Reduce `app.py` to routing and rendering**

Replace the body of `warden/broker/app.py` below its imports. Keep the module docstring's first paragraph, keep `now()`, and delete `_args_digest`, `_refuse_unauthenticated`, `_backend_fault`, `_write_deny_record` and `_deny` — they now live in the spine.

```python
def _render(outcome: Outcome) -> JSONResponse:
    """One Outcome, one response. Pure: rendering twice changes nothing,
    because every side effect already happened in the spine."""
    if outcome.kind is Kind.EXECUTED:
        return JSONResponse(
            {"content": outcome.result.content, "rows": outcome.result.rows}
        )
    if outcome.kind is Kind.UNAUTHENTICATED:
        return JSONResponse(
            {"error": UNAUTHENTICATED, "message": outcome.message}, status_code=401
        )
    if outcome.kind in AUDIT_UNAVAILABLE:
        return JSONResponse(
            {"error": "audit_unavailable", "message": outcome.message}, status_code=503
        )
    if outcome.kind in FAULT:
        return JSONResponse(
            {"error": "backend_error", "message": outcome.message}, status_code=502
        )
    if outcome.kind in DENIED:
        return JSONResponse(
            {
                "error": "policy_denied",
                "rule": outcome.rule,
                "message": outcome.message,
            },
            status_code=403,
            headers={"X-Warden-Rule": outcome.rule},
        )
    raise ValueError(f"no HTTP rendering for {outcome.kind}")


async def _parse_args(request: Request) -> dict | None:
    """Returns the "args" object, or None if the body is not JSON, not an
    object, or has an "args" that is not itself an object -- any of which
    means there is no well-formed request to decide about."""
    try:
        body = await request.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    args = body.get("args", {})
    if not isinstance(args, dict):
        return None
    return args


def _credential(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ")


def create_app(
    *,
    verifier: Verifier,
    pdp: PolicyDecisionPoint,
    taint: TaintTracker,
    audit: AuditLog,
    catalog: ToolCatalog,
    policy_digest: str,
    clock: Callable[[], int] | None = None,
) -> FastAPI:
    app = FastAPI(title="warden broker")
    spine = Spine(
        verifier=verifier,
        pdp=pdp,
        taint=taint,
        audit=audit,
        catalog=catalog,
        policy_digest=policy_digest,
        clock=clock or now,
    )
    # Reachable by any surface mounted onto this app later. There is exactly
    # one spine per app, which is what makes two front doors incapable of
    # deciding differently.
    app.state.spine = spine

    @app.post("/v1/tools/{tool}/invoke")
    async def invoke(tool: str, request: Request) -> JSONResponse:
        # The only await, and it is here rather than in the spine: past this
        # line the whole sequence is synchronous, so the snapshot-to-record
        # window cannot be interleaved by construction.
        credential = _credential(request)
        args = None if credential is None else await _parse_args(request)
        return _render(spine.handle_tool_call(credential, tool, args))

    return app
```

Update the imports at the top of `app.py`:

```python
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from warden.broker.audit import AuditLog
from warden.broker.config.catalog import ToolCatalog
from warden.broker.identity import Verifier
from warden.broker.pdp import PolicyDecisionPoint
from warden.broker.spine import (
    AUDIT_UNAVAILABLE,
    DENIED,
    FAULT,
    UNAUTHENTICATED,
    Kind,
    Outcome,
    Spine,
)
from warden.broker.taint import TaintTracker
```

> **Note the `args = None if credential is None else ...`**: the unauthenticated path must never read the body. Reading it first would add a failure mode to a path whose whole job is to refuse and record.

- [ ] **Step 3: Run the existing suite — it is the acceptance criterion**

Run: `.venv/bin/pytest tests/warden/test_app.py -q`
Expected: all pass, unchanged. Any failure is a behaviour change and must be fixed in the spine, not in the test.

- [ ] **Step 4: Write the spine's own tests**

Create `tests/warden/test_spine.py`:

```python
"""The spine's contract: every variant reachable, rendering pure."""

from __future__ import annotations

import pytest

from warden.broker.app import _render
from warden.broker.spine import (
    AUDIT_UNAVAILABLE,
    DENIED,
    FAULT,
    Kind,
    Outcome,
)


def test_every_kind_has_an_http_rendering():
    """Totality. A Kind nobody rendered is a variant that 500s in production."""
    unrenderable = []
    for kind in Kind:
        if kind is Kind.LISTED:
            continue  # ListOutcome, not Outcome -- rendered by list surfaces
        outcome = Outcome(kind=kind, rule="r", message="m")
        if kind is Kind.EXECUTED:
            continue  # covered by test_app.py, needs a real ToolResult
        try:
            _render(outcome)
        except ValueError:
            unrenderable.append(kind)
    assert unrenderable == []


def test_the_three_groupings_are_disjoint_and_cover_every_failure():
    assert not (DENIED & AUDIT_UNAVAILABLE)
    assert not (DENIED & FAULT)
    assert not (AUDIT_UNAVAILABLE & FAULT)
    accounted = DENIED | AUDIT_UNAVAILABLE | FAULT | {
        Kind.EXECUTED, Kind.LISTED, Kind.UNAUTHENTICATED
    }
    assert set(Kind) == accounted
```

- [ ] **Step 5: Add the rendering-idempotence test**

Append to `tests/warden/test_spine.py`:

```python
def test_rendering_an_outcome_twice_has_no_side_effects(tmp_path):
    """Rendering is pure. If a renderer applied the taint update or wrote the
    audit record, two surfaces could apply it twice, or in a different order
    relative to each other, and the row budget would drift with no signal."""
    from tests.warden.test_app import Clock, build, invoke, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    spine = client.app.state.spine

    token = token_for(signer)
    outcome = spine.handle_tool_call(token, "read_document", {"doc_id": "a"})

    before_records = len(audit.records())
    before_state = spine._taint.snapshot("4711")

    _render(outcome)
    _render(outcome)

    assert len(audit.records()) == before_records
    assert spine._taint.snapshot("4711") == before_state
```

- [ ] **Step 6: Pin that a PDP outage still denies**

Append to `tests/warden/test_spine.py`:

```python
def test_a_pdp_outage_denies_rather_than_faulting(tmp_path):
    """pdp.unavailable is POLICY_DENIED carrying that rule -- a 403, not a
    5xx. It is the one deny rule the policy bundle does not produce, and
    mapping it to a fault status would pass every other test in the suite."""
    import httpx

    from tests.warden.test_app import build, invoke, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    # An OPA that answers with something incoherent: allow=True alongside a
    # non-empty deny_reasons, which pdp.py refuses to trust.
    client, _ = build(
        tmp_path, signer, {"allow": True, "deny_reasons": ["rows.bounded"]}
    )
    response = invoke(client, token_for(signer), "read_document", {"doc_id": "a"})
    assert response.status_code == 403
    assert response.json()["rule"] == "pdp.unavailable"
```

- [ ] **Step 7: Run everything**

Run: `.venv/bin/pytest tests/warden/ -q`
Expected: all pass except the 21 pre-existing `test_golden_decisions.py` OPA errors.

- [ ] **Step 8: Commit**

```bash
git add warden/broker/spine.py warden/broker/app.py tests/warden/test_spine.py
git commit -m "refactor: make the decision sequence a value, so a second surface cannot drift"
```

---

### Task 5: `tools/list` in the spine, and a replay that can render it

The list refusal writes a record with an action shape nothing has seen before. `warden replay` must not print `?()` into the hash chain.

**Files:**
- Modify: `warden/cli/replay.py` (the `_describe` renderer)
- Test: `tests/warden/test_spine.py` (append), `tests/warden/test_golden_replay.py` (unchanged, must still pass)

**Interfaces:**
- Consumes: `Spine.list_tools` from Task 4.
- Produces: replay renders `{"type": "tool_list"}` as `list_tools()`. Task 12 relies on `list_tools` filtering.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_spine.py`:

```python
def test_listing_is_filtered_by_the_token_and_records_nothing(tmp_path):
    from tests.warden.test_app import build, token_for
    from warden.broker.identity import Signer
    from warden.broker.spine import Kind

    signer = Signer.generate()
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    spine = client.app.state.spine

    # The token grants three of the catalog's four tools.
    outcome = spine.list_tools(token_for(signer))
    assert outcome.kind is Kind.LISTED
    assert outcome.tools == ("http_fetch", "query_customers", "read_document")
    assert audit.records() == []


def test_an_unauthenticated_listing_is_refused_and_recorded(tmp_path):
    from tests.warden.test_app import build
    from warden.broker.identity import Signer
    from warden.broker.spine import Kind

    signer = Signer.generate()
    client, audit = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    spine = client.app.state.spine

    outcome = spine.list_tools(None)
    assert outcome.kind is Kind.UNAUTHENTICATED
    assert outcome.tools == ()
    records = audit.records()
    assert len(records) == 1
    assert records[0]["action"] == {"type": "tool_list"}
    assert records[0]["agent_id"] == "unauthenticated"
    assert records[0]["rule"] == "unauthenticated"


def test_replay_renders_a_list_refusal(tmp_path):
    """A record shape the renderer has never seen prints as `?()` -- an
    illegible line in the same hash chain as real decisions."""
    from warden.cli.replay import _describe

    rendered = _describe({
        "action": {"type": "tool_list"},
        "target": {"kind": "unknown"},
    })
    assert rendered == "list_tools()"
```

- [ ] **Step 2: Run — expect the third to fail**

Run: `.venv/bin/pytest tests/warden/test_spine.py -q -k "listing or replay_renders"`
Expected: the first two PASS (Task 4 built them), `test_replay_renders_a_list_refusal` FAILS.

- [ ] **Step 3: Teach the renderer the new action**

In `warden/cli/replay.py`, at the top of `_describe`, add:

```python
    if record["action"].get("type") == "tool_list":
        # A listing carries no tool name -- it is the question "which tools
        # may I call", refused. Without this the renderer falls through to
        # the tool_call branch and prints `?()`.
        return "list_tools()"
```

- [ ] **Step 4: Run replay's own goldens too**

Run: `.venv/bin/pytest tests/warden/test_spine.py tests/warden/test_golden_replay.py -q`
Expected: all pass. The goldens must be untouched — this adds a branch, it does not change an existing one.

- [ ] **Step 5: Commit**

```bash
git add warden/cli/replay.py tests/warden/test_spine.py
git commit -m "feat: list tools per token, and render a refused listing in replay"
```

---

### Task 6: Tool-table key allowlist, `description` and `title`

`[tools.x] descriptoin = "..."` loads clean today. That is the failure `_ARG_KEYS` and `_check_binding_keys` already exist to prevent, one level up — and with MCP it advertises a tool to a model with no description.

**Files:**
- Modify: `warden/broker/config/catalog.py`
- Test: `tests/warden/test_catalog.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: `CatalogEntry` gains `description: str = ""` and `title: str = ""`; `ToolCatalog.entry(tool)` exposes them. Tasks 9 and 11 read them.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_catalog.py`:

```python
def test_an_unknown_tool_table_key_is_refused(tmp_path):
    """A typo that silently disables a check is the failure the arg and
    binding allowlists exist to prevent. The tool table itself had none."""
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.lookup]\n'
        'kind = "docstore"\n'
        'descriptoin = "a typo"\n'
        '[tools.lookup.binding]\n'
        'base_url = "http://example.invalid"\n'
        '[tools.lookup.args]\n'
        'doc_id = { type = "string", required = true }\n'
    )
    with pytest.raises(ConfigError, match="descriptoin"):
        load_catalog(manifest, env={}, client=None)


def test_description_and_title_reach_the_entry(tmp_path):
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.lookup]\n'
        'kind = "docstore"\n'
        'title = "Document lookup"\n'
        'description = "Fetch one document by id."\n'
        '[tools.lookup.binding]\n'
        'base_url = "http://example.invalid"\n'
        '[tools.lookup.args]\n'
        'doc_id = { type = "string", required = true }\n'
    )
    catalog = load_catalog(manifest, env={}, client=None)
    entry = catalog.entry("lookup")
    assert entry.title == "Document lookup"
    assert entry.description == "Fetch one document by id."


def test_a_non_string_description_is_refused(tmp_path):
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.lookup]\n'
        'kind = "docstore"\n'
        'description = 42\n'
        '[tools.lookup.binding]\n'
        'base_url = "http://example.invalid"\n'
        '[tools.lookup.args]\n'
        'doc_id = { type = "string", required = true }\n'
    )
    with pytest.raises(ConfigError, match="description"):
        load_catalog(manifest, env={}, client=None)
```

Ensure `pytest`, `ConfigError` and `load_catalog` are imported at the top of that file.

- [ ] **Step 2: Run — expect three failures**

Run: `.venv/bin/pytest tests/warden/test_catalog.py -q`
Expected: the three new tests FAIL.

- [ ] **Step 3: Add the allowlist and the fields**

In `warden/broker/config/catalog.py`, add near the other module constants:

```python
# Every key a [tools.<tool>] table may carry. The [args] vocabulary and the
# [binding] keys each have an allowlist already (schema.py's _ARG_KEYS,
# _check_binding_keys below); the tool table itself had none, so a misspelt
# key was read by nobody and reported by nobody. With a tool description now
# reaching a model, a silently-dropped `descriptoin` is a tool the model
# will misuse.
_TOOL_KEYS = ("kind", "binding", "args", "unknown_args", "description", "title")


def _check_tool_keys(tool: str, table: dict) -> None:
    for key in table:
        if key not in _TOOL_KEYS:
            raise ConfigError(
                f"tool {tool!r}: unknown key {key!r}; "
                f"expected one of {sorted(_TOOL_KEYS)}"
            )


def _text(tool: str, table: dict, key: str) -> str:
    value = table.get(key, "")
    if not isinstance(value, str):
        raise ConfigError(f"tool {tool!r}: {key} must be a string")
    return value
```

Extend `CatalogEntry`:

```python
@dataclass(frozen=True)
class CatalogEntry:
    kind: str
    target_kind: str
    schema: ToolSchema
    adapter: object
    # Advertised to a model by the MCP surface, and unused by every other
    # caller. Empty is legal here and rejected by `warden config check` only
    # when that surface is switched on.
    description: str = ""
    title: str = ""
```

In `load_catalog`'s per-tool loop, call `_check_tool_keys(tool, table)` as the **first** statement after the `isinstance(table, dict)` guard, and add to the `CatalogEntry(...)` construction:

```python
            description=_text(tool, table, "description"),
            title=_text(tool, table, "title"),
```

- [ ] **Step 4: Run the catalog and seam tests**

Run: `.venv/bin/pytest tests/warden/test_catalog.py tests/test_seam.py tests/warden/test_arg_schema.py -q`
Expected: all pass. `test_seam.py:213-220` pins `load_catalog`'s ConfigError message ordering — if it fails, `_check_tool_keys` is in the wrong position.

- [ ] **Step 5: Commit**

```bash
git add warden/broker/config/catalog.py tests/warden/test_catalog.py
git commit -m "feat: allowlist tool-table keys, and carry description and title"
```

---

### Task 7: Generate `inputSchema`

**Files:**
- Create: `warden/broker/schema_json.py`
- Test: `tests/warden/test_schema_json.py`

**Interfaces:**
- Consumes: `ToolSchema`, `ArgSpec` from `warden.broker.config.schema`.
- Produces: `json_schema(schema: ToolSchema) -> dict` — a JSON Schema 2020-12 object schema. Task 11 calls it. Raises `ConfigError` on an `ArgSpec.type` it cannot map.

- [ ] **Step 1: Write the failing tests**

Create `tests/warden/test_schema_json.py`:

```python
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
```

- [ ] **Step 2: Run — expect an import error**

Run: `.venv/bin/pytest tests/warden/test_schema_json.py -q`
Expected: FAIL, `ModuleNotFoundError: warden.broker.schema_json`. If `jsonschema` is also missing, install it — it arrives with `mcp` in Task 10, and for now: `.venv/bin/pip install "jsonschema>=4.20.0"`.

- [ ] **Step 3: Write the generator**

Create `warden/broker/schema_json.py`:

```python
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
```

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/pytest tests/warden/test_schema_json.py -q`
Expected: all pass. If the property test reports disagreements, the mapping is wrong — fix `_property`, not the test.

- [ ] **Step 5: Commit**

```bash
git add warden/broker/schema_json.py tests/warden/test_schema_json.py
git commit -m "feat: generate a JSON Schema that agrees with the enforced one"
```

---

### Task 8: The `[mcp]` config section

**Files:**
- Modify: `warden/broker/config/loader.py`
- Test: `tests/warden/test_config_loader.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: `McpConfig(enabled: bool, path: str, host: str)` frozen dataclass; `BrokerConfig.mcp: McpConfig`. Task 10 reads it in `__main__.py`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_config_loader.py`:

```python
def test_mcp_is_absent_and_therefore_disabled(tmp_path):
    """Every existing warden.toml has no [mcp]. Absent must mean off, and it
    must be structural rather than a comment: _section() raises on a missing
    section, so reading [mcp] through it would stop every one of these
    configs from loading at all."""
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.mcp.enabled is False
    assert config.mcp.path == "/mcp"


def test_mcp_is_read_when_present(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(
        path.read_text()
        + '\n[mcp]\nenabled = true\npath = "/tools/mcp"\nhost = "broker.internal"\n'
    )
    config = load_broker_config(path, env={})
    assert config.mcp.enabled is True
    assert config.mcp.path == "/tools/mcp"
    assert config.mcp.host == "broker.internal"


def test_a_non_boolean_enabled_is_refused(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(path.read_text() + '\n[mcp]\nenabled = "yes"\n')
    with pytest.raises(ConfigError, match="mcp.enabled"):
        load_broker_config(path, env={})


def test_a_malformed_mcp_section_names_itself(tmp_path):
    path = write_complete_config(tmp_path)
    # PREPENDED, not appended. A bare key written after a table header belongs
    # to that table, so appending `mcp = "..."` below [catalog] parses as
    # catalog.mcp and never reaches the top level this test is about.
    path.write_text('mcp = "not a table"\n' + path.read_text())
    with pytest.raises(ConfigError, match=r"\[mcp\]"):
        load_broker_config(path, env={})
```

If `write_complete_config` does not already exist in that file, extract the existing complete-config fixture (around lines 23–44) into a module-level helper of that name returning the written `Path`, and update its current caller to use it.

- [ ] **Step 2: Run — expect four failures**

Run: `.venv/bin/pytest tests/warden/test_config_loader.py -q`
Expected: the four new tests FAIL with `AttributeError: 'BrokerConfig' object has no attribute 'mcp'`.

- [ ] **Step 3: Add the helpers and the dataclass**

In `warden/broker/config/loader.py`, after `_section`:

```python
def _optional_section(document: dict, name: str) -> dict:
    """A section that may legitimately be absent.

    _section() raises on a missing table, which is right for the six the
    broker cannot run without. A surface that is off by default is the
    opposite case: every config written before it existed has no such table,
    and all of them must keep loading.
    """
    value = document.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"malformed section [{name}]")
    return value


def _flag(section: dict, table: str, key: str) -> bool:
    """A strict boolean. Duplicated from config/schema.py rather than
    imported: schema.py imports ConfigError from here, so the other
    direction is a cycle. Four lines is cheaper than restructuring both."""
    value = section.get(key, False)
    if not isinstance(value, bool):
        raise ConfigError(f"{table}.{key} must be true or false")
    return value
```

Add the dataclass above `BrokerConfig`:

```python
@dataclass(frozen=True)
class McpConfig:
    """The MCP surface's wiring. Off unless a deployment says otherwise.

    `host` is handed to the SDK's transport-security settings. Left unset,
    the SDK infers a loopback host and turns on DNS-rebinding protection,
    which answers 421 to every request arriving under a real hostname.
    """

    enabled: bool = False
    path: str = "/mcp"
    host: str = ""
```

Add the field to `BrokerConfig` (after `catalog_path`):

```python
    mcp: McpConfig = McpConfig()
```

- [ ] **Step 4: Parse it**

In `load_broker_config`, before the `return`:

```python
    mcp = _optional_section(document, "mcp")
```

and add to the `BrokerConfig(...)` construction:

```python
        mcp=McpConfig(
            enabled=_flag(mcp, "mcp", "enabled"),
            path=_string(mcp, "mcp", "path", env) if "path" in mcp else "/mcp",
            host=_string(mcp, "mcp", "host", env) if "host" in mcp else "",
        ),
```

- [ ] **Step 5: Run the loader tests**

Run: `.venv/bin/pytest tests/warden/test_config_loader.py -q`
Expected: all pass, including the twenty that predate this change.

- [ ] **Step 6: Commit**

```bash
git add warden/broker/config/loader.py tests/warden/test_config_loader.py
git commit -m "feat: read an optional [mcp] section that is off unless asked for"
```

---

### Task 9: `warden config check` learns about MCP

**Files:**
- Modify: `warden/broker/config/check.py`
- Modify: `warden/cli/main.py`, `warden/cli/replay.py` (both front doors)
- Test: `tests/warden/test_config_check.py` (append)

**Interfaces:**
- Consumes: `CatalogEntry.description`/`.title` (Task 6), `json_schema` (Task 7).
- Produces: `check_catalog(..., *, opa_url=None, mcp_enabled: bool = False)`. The new parameter is **keyword-only with a default**, because roughly eighteen tests call this positionally.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_config_check.py`:

```python
def test_a_missing_description_is_only_a_problem_when_mcp_is_on(tmp_path):
    """A deployment that never turns the surface on is unaffected. One that
    does cannot half-configure it: a tool with no description is a tool the
    model will misuse."""
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.lookup]\n'
        'kind = "docstore"\n'
        '[tools.lookup.binding]\n'
        'base_url = "http://example.invalid"\n'
        '[tools.lookup.args]\n'
        'doc_id = { type = "string", required = true }\n'
    )
    data = tmp_path / "data.json"
    data.write_text('{"tools": {"lookup": {"target_kind": "doc"}}}')

    assert check_catalog(manifest, data, env={}) == []
    problems = check_catalog(manifest, data, env={}, mcp_enabled=True)
    assert any("description" in p for p in problems)
    assert any("title" in p for p in problems)


def test_required_plus_null_is_absent_is_refused_under_mcp(tmp_path):
    """Faithful as a schema, unsound on the wire: clients and serializers
    drop null-valued properties, so an accepted {"body": null} arrives as {}
    and is refused as missing-required."""
    manifest = tmp_path / "tools.toml"
    manifest.write_text(
        '[tools.fetch]\n'
        'kind = "http"\n'
        'title = "Fetch"\n'
        'description = "Fetch a URL."\n'
        '[tools.fetch.binding]\n'
        'data_class = "public"\n'
        '[tools.fetch.args]\n'
        'url = { type = "string", required = true }\n'
        'body = { type = "string", required = true, null_is_absent = true }\n'
    )
    data = tmp_path / "data.json"
    data.write_text('{"tools": {"fetch": {"target_kind": "http"}}}')
    problems = check_catalog(manifest, data, env={}, mcp_enabled=True)
    assert any("null_is_absent" in p and "required" in p for p in problems)


def test_the_shipped_manifest_stays_clean_without_mcp(tmp_path):
    """The demo's manifest declares no description or title yet. It must not
    start failing the check it passes today."""
    from demo.scenario.catalog import MANIFEST

    data = Path("demo/scenario/data.json")
    problems = check_catalog(
        MANIFEST,
        data,
        env={
            "DOCSTORE_URL": "http://example.invalid",
            "DB_PATH": str(tmp_path / "x.db"),
            "MAILER_URL": "http://example.invalid",
        },
    )
    assert problems == []
```

- [ ] **Step 2: Run — expect two failures**

Run: `.venv/bin/pytest tests/warden/test_config_check.py -q`
Expected: the first two new tests FAIL with `TypeError: unexpected keyword argument 'mcp_enabled'`; the third passes.

- [ ] **Step 3: Add the checks**

In `warden/broker/config/check.py`, add:

```python
def _mcp_problems(catalog, catalog_path) -> list[str]:
    """What a tool must carry before it is advertised to a model.

    Only reached when the surface is switched on, so a deployment that never
    enables it sees none of this.
    """
    problems: list[str] = []
    for tool in sorted(catalog.names()):
        entry = catalog.entry(tool)
        for field in ("description", "title"):
            if not getattr(entry, field).strip():
                problems.append(
                    f"{tool}: no {field}; the MCP surface advertises this tool "
                    f"to a model, which needs one to use it correctly"
                )
        try:
            json_schema(entry.schema)
        except ConfigError as exc:
            problems.append(f"{tool}: cannot be advertised ({exc})")
        for name, spec in entry.schema.args.items():
            if spec.required and spec.null_is_absent:
                problems.append(
                    f"{tool}.{name}: required together with null_is_absent. "
                    f"Clients drop null-valued properties before sending, so "
                    f"an accepted null arrives as a missing required argument"
                )
        if entry.schema.unknown_args == "allow":
            fields = getattr(entry.adapter, "_fields", None)
            if fields:
                problems.append(
                    f"{tool}: unknown_args = \"allow\" on an adapter that "
                    f"forwards only {sorted(fields)}. The advertised schema "
                    f"would tell a model an argument is meaningful that is "
                    f"then dropped on the way out"
                )
    return problems
```

Add the imports `from warden.broker.config.loader import ConfigError` and `from warden.broker.schema_json import json_schema` at the top.

Change `check_catalog`'s signature and body:

```python
def check_catalog(
    catalog_path: Path,
    data_path: Path,
    env: Mapping[str, str],
    *,
    opa_url: str | None = None,
    mcp_enabled: bool = False,
) -> list[str]:
```

and after `problems.extend(_arg_binding_problems(catalog, catalog_path))`:

```python
    if mcp_enabled:
        problems.extend(_mcp_problems(catalog, catalog_path))
```

> **On `_fields`:** confirm the attribute name the mail adapter stores `binding.fields` under by reading `warden/broker/adapters/mail.py`. If it differs, use the real name; `getattr(..., None)` keeps the check inert for adapters that have no such allowlist.

- [ ] **Step 4: Wire both front doors**

In `warden/cli/main.py`, add to `p_check` in `build_parser()`:

```python
    p_check.add_argument(
        "--mcp",
        action="store_true",
        help="also check what the MCP surface requires of each tool",
    )
```

and in `_cmd_config_check`, pass `mcp_enabled=args.mcp` to `check_catalog(...)`.

Do the same in `warden/cli/replay.py`'s `config` command — the independent second front door, and the one CI invokes. Add the same `--mcp` flag to its parser and forward it.

- [ ] **Step 5: Run the check tests and the CLI**

Run: `.venv/bin/pytest tests/warden/test_config_check.py tests/warden/test_cli_config_errors.py -q`
Then: `.venv/bin/python -m warden.cli.replay config --catalog demo/scenario/tools.toml --data demo/scenario/data.json` with `DOCSTORE_URL`, `DB_PATH` and `MAILER_URL` set, and confirm it still prints `config consistent`.
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add warden/broker/config/check.py warden/cli/main.py warden/cli/replay.py tests/warden/test_config_check.py
git commit -m "feat: check what MCP requires of a tool, on both config front doors"
```

---

### Task 10: The optional extra, and silencing telemetry

**Files:**
- Modify: `warden/pyproject.toml`, `warden/broker/__main__.py`
- Test: `tests/warden/test_entry_points.py` (append), `tests/warden/test_mcp_surface.py` (create)

**Interfaces:**
- Consumes: `McpConfig` (Task 8).
- Produces: `pip install -e './warden[mcp]'` installs the SDK. `warden/broker/mcp.py` is imported lazily and only when `config.mcp.enabled`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_entry_points.py`:

```python
def test_the_mcp_sdk_is_an_extra_not_a_dependency():
    """The enforcement point is the one service a subverted agent can reach
    on two ports. A second HTTP stack and a telemetry library belong to the
    surface that needs them, not to every deployment."""
    warden = project("warden")
    joined = " ".join(warden["dependencies"])
    assert "mcp" not in joined
    assert any(d.startswith("mcp==") for d in warden["optional-dependencies"]["mcp"])
```

Create `tests/warden/test_mcp_surface.py`:

```python
"""The MCP surface: mounted, authenticated, and off unless asked for."""

from __future__ import annotations

import pytest

mcp = pytest.importorskip("mcp", reason="requires the warden[mcp] extra")
```

- [ ] **Step 2: Run — expect one failure**

Run: `.venv/bin/pytest tests/warden/test_entry_points.py -q`
Expected: `test_the_mcp_sdk_is_an_extra_not_a_dependency` FAILS with `KeyError: 'optional-dependencies'`.

- [ ] **Step 3: Declare the extra**

In `warden/pyproject.toml`, after `dependencies`:

```toml
# The MCP surface's dependencies, and only its. mcp pulls a second HTTP
# stack (httpx2, alongside the pinned httpx) plus opentelemetry-api into
# whatever process installs it, so a deployment that never enables the
# surface never carries them. The broker raises at boot if [mcp] is enabled
# and this extra is absent, rather than discovering it at the first request.
[project.optional-dependencies]
mcp = [
  "mcp==2.0.0",
]
```

- [ ] **Step 4: Install the extra and neutralise telemetry**

Run: `.venv/bin/pip install -e './warden[mcp]'`

In `warden/broker/__main__.py`, add:

```python
def _silence_telemetry() -> None:
    """The MCP SDK installs an OpenTelemetry middleware as its outermost
    layer. In an image that also carries the OTel SDK with the standard
    environment variables set, the enforcement point would begin exporting
    spans -- tool names and request ids -- to a collector. That is network
    egress from the one process whose whole premise is being the only route
    out, and it appears in no audit record. A no-op provider costs nothing
    and closes it.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.trace import NoOpTracerProvider
    except ImportError:
        return
    trace.set_tracer_provider(NoOpTracerProvider())
```

Call `_silence_telemetry()` as the first statement of `build()`.

- [ ] **Step 5: Add the telemetry test**

Append to `tests/warden/test_mcp_surface.py`:

```python
def test_telemetry_is_a_no_op_after_the_broker_boots():
    from opentelemetry import trace

    from warden.broker.__main__ import _silence_telemetry

    _silence_telemetry()
    provider = trace.get_tracer_provider()
    assert type(provider).__name__ == "NoOpTracerProvider"
```

- [ ] **Step 6: Run**

Run: `.venv/bin/pytest tests/warden/test_entry_points.py tests/warden/test_mcp_surface.py -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add warden/pyproject.toml warden/broker/__main__.py tests/warden/test_entry_points.py tests/warden/test_mcp_surface.py
git commit -m "feat: take the MCP SDK as an extra, and silence the telemetry it brings"
```

---

### Task 11: The MCP surface — `tools/call`

**Files:**
- Create: `warden/broker/mcp.py`
- Modify: `warden/broker/app.py` (accept `mcp=`), `warden/broker/__main__.py` (pass it)
- Test: `tests/warden/test_mcp_surface.py` (append)

**Interfaces:**
- Consumes: `Spine`, `Outcome`, `Kind`, the grouping frozensets (Task 4); `json_schema` (Task 7); `McpConfig` (Task 8); `CatalogEntry.description`/`.title` (Task 6).
- Produces: `mount_mcp(app: FastAPI, *, spine: Spine, catalog: ToolCatalog, config: McpConfig) -> None`. `create_app(..., mcp: McpConfig | None = None)`.

> **`mcp` reaches `create_app` as its own parameter, never through `BrokerComponents`.** `as_proxy_kwargs()` returns `as_app_kwargs()` verbatim, and `authorize_connect` is keyword-only with no `**kwargs` — so a new key there raises `TypeError` inside *every* CONNECT, at request time, while the broker still reports healthy.

- [ ] **Step 1: Write the failing tests**

Append to `tests/warden/test_mcp_surface.py`:

```python
from fastapi.testclient import TestClient


def test_the_surface_is_absent_unless_enabled(tmp_path):
    from tests.warden.test_app import build

    from warden.broker.identity import Signer

    signer = Signer.generate()
    client, _ = build(tmp_path, signer, {"allow": True, "deny_reasons": []})
    assert not any(getattr(r, "path", "").startswith("/mcp") for r in client.app.routes)
    assert client.post("/mcp").status_code == 404


def test_a_call_is_decided_by_the_same_spine(tmp_path):
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        result = call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})
        assert result.is_error is False
        assert "doc-body" in result.content[0].text
        assert [r["decision"] for r in audit.records()] == ["allow"]


def test_a_denial_is_a_tool_error_naming_the_rule(tmp_path):
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(
        tmp_path, signer, {"allow": False, "deny_reasons": ["rows.bounded"]}
    ) as (client, audit):
        result = call_tool(client, token_for(signer), "read_document", {"doc_id": "a"})
        assert result.is_error is True
        assert "rows.bounded" in result.content[0].text
        assert [r["decision"] for r in audit.records()] == ["deny"]
```

Add to `tests/warden/test_app.py` a context-managed builder and a call helper (imported above):

```python
import contextlib


@contextlib.contextmanager
def build_with_mcp(
    tmp_path, signer, opa_payload, backend_handler=None, clock=None, opa_handler=None
):
    """build(), with the MCP surface mounted -- and entered as a context
    manager, because a mounted sub-app's lifespan never runs on its own and
    the session manager must be started.

    `opa_handler` overrides `opa_payload` for a test that needs OPA to answer
    differently depending on what it is asked -- a budget that runs out, say.
    Injected at construction like every other collaborator here, so no test
    has to reach through the app to swap a client afterwards.
    """
    from warden.broker.config.loader import McpConfig

    db = tmp_path / "customers.db"
    seed_customers(db, count=120)

    if opa_handler is None:
        def opa_handler(request):
            return httpx.Response(200, json={"result": opa_payload})

    backend_handler = backend_handler or (
        lambda request: httpx.Response(200, text="doc-body")
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(
        verifier=Verifier(signer.public_key_pem()),
        pdp=PolicyDecisionPoint(
            "http://opa:8181",
            client=httpx.Client(transport=httpx.MockTransport(opa_handler)),
        ),
        taint=TaintTracker(),
        audit=audit,
        catalog=demo_catalog(
            docstore_url="http://docstore.internal",
            db_path=db,
            mailer_url="http://mailer.internal",
            client=httpx.Client(transport=httpx.MockTransport(backend_handler)),
        ),
        policy_digest="sha256:test",
        clock=clock,
        mcp=McpConfig(enabled=True, path="/mcp", host="testserver"),
    )
    with TestClient(app) as client:
        yield client, audit
```

and in `tests/warden/test_mcp_surface.py`:

```python
def call_tool(client, token, name, arguments):
    """Drive tools/call over the mounted surface with the SDK's own client."""
    import anyio
    from mcp.client.streamable_http import streamable_http_client
    from mcp import Client

    async def go():
        async with streamable_http_client(
            "http://testserver/mcp",
            headers={"Authorization": f"Bearer {token}"},
            http_client=client_transport(client),
        ) as streams:
            async with Client(*streams) as session:
                return await session.call_tool(name, arguments)

    return anyio.run(go)
```

> **`client_transport(client)`:** the SDK's client needs an `httpx2.AsyncClient` whose transport routes into the `TestClient`'s ASGI app rather than the network. Implement it as
> `httpx2.AsyncClient(transport=httpx2.ASGITransport(app=client.app), base_url="http://testserver", trust_env=False)`.
> If `streamable_http_client` does not accept an `http_client=` keyword in 2.0.0, run the app under a real loopback port with `uvicorn` in a thread fixture instead, and record which approach was used in the test module's docstring.

- [ ] **Step 2: Run — expect failures**

Run: `.venv/bin/pytest tests/warden/test_mcp_surface.py -q`
Expected: `test_the_surface_is_absent_unless_enabled` PASSES (nothing is mounted yet); the other two FAIL on `ImportError: build_with_mcp`.

- [ ] **Step 3: Write `warden/broker/mcp.py`**

```python
"""An MCP front door onto the same decision sequence.

This module renders. It does not decide, it does not audit, and it does not
normalise: every one of those happens in the spine, which the HTTP surface
calls with the same arguments and gets the same Outcome from. A front door
that was free to interpret a request on its way past would be free to
disagree with the one the broker already has.

Two renderings matter more than the rest.

A policy refusal comes back as a TOOL EXECUTION error rather than a protocol
error, because a model that can read a refusal adapts and one that receives a
transport fault retries the identical call. That is the difference between a
task that finishes after being refused and a loop.

A failure that happened AFTER the action was carried out is phrased so it
cannot be read as retryable. Those calls already did something -- sent the
mail, read the rows -- and the taint update never ran, so a retry would pass
the same budget check a second time.

No exception text is rendered to a caller anywhere in here. On the older
protocol revision an unhandled error is emitted verbatim, and the two live
sources of one in this system are the audit log's own filesystem errors and
the policy client's -- neither of which belongs in a model's context.
"""

from __future__ import annotations

from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.lowlevel.server import ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Mount

from warden.broker.schema_json import json_schema
from warden.broker.spine import AUDIT_UNAVAILABLE, DENIED, FAULT, Kind, Outcome

# Rendered instead of an exception message, which on the handshake-era
# protocol reaches the caller verbatim.
OPAQUE_FAULT = "The tool could not be completed. The failure was recorded."

AFTER_THE_FACT = (
    "The tool could not be completed, and the action it authorised may "
    "already have been performed. Do not repeat this call."
)


def _credential(ctx: ServerRequestContext) -> str | None:
    request = getattr(ctx, "request", None)
    header = (getattr(request, "headers", {}) or {}).get("authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.removeprefix("Bearer ")


def _text(message: str, *, is_error: bool) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=is_error
    )


def render_call(outcome: Outcome) -> types.CallToolResult:
    if outcome.kind is Kind.EXECUTED:
        return _text(outcome.result.content, is_error=False)
    if outcome.kind in DENIED:
        return _text(outcome.message, is_error=True)
    if outcome.kind in (
        Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW,
        Kind.TAINT_REJECTED_AFTER_EXECUTE,
    ):
        return _text(f"{AFTER_THE_FACT} (record {outcome.audit_seq})", is_error=True)
    if outcome.kind is Kind.DESCRIBE_BACKEND_FAULT:
        return _text(OPAQUE_FAULT, is_error=True)
    if outcome.kind is Kind.UNAUTHENTICATED:
        # Not a tool error: there is nothing for a model to adapt to, and a
        # caller has to be told to present a credential.
        raise types.MCPError(code=-32001, message="Unauthenticated.")
    if outcome.kind in AUDIT_UNAVAILABLE:
        raise types.MCPError(code=-32002, message="Audit log unavailable.")
    raise types.MCPError(code=-32603, message=OPAQUE_FAULT)


def mount_mcp(app, *, spine, catalog, config) -> None:
    """Mounts the surface onto an existing app, sharing its one spine."""

    def _tool(name: str) -> types.Tool:
        entry = catalog.entry(name)
        return types.Tool(
            name=name,
            title=entry.title,
            description=entry.description,
            input_schema=json_schema(entry.schema),
        )

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        try:
            outcome = spine.list_tools(_credential(ctx))
            if outcome.kind is Kind.LISTED:
                return types.ListToolsResult(
                    tools=[_tool(name) for name in outcome.tools]
                )
            # A listing has no is_error channel, so a refusal has to be a
            # protocol error. An empty list would be indistinguishable from a
            # catalog that legitimately grants nothing.
            raise types.MCPError(code=-32001, message="Unauthenticated.")
        except types.MCPError:
            raise
        except Exception:
            raise types.MCPError(code=-32603, message=OPAQUE_FAULT) from None

    async def on_call_tool(ctx, params) -> types.CallToolResult:
        try:
            # `arguments: null` is how a caller invokes a tool with no
            # arguments, so it normalises to {} -- matching what the HTTP
            # body parser does with a missing "args". None is reserved here
            # for a body that did not parse at all, which this transport
            # cannot produce.
            arguments: dict[str, Any] = params.arguments or {}
            return render_call(
                spine.handle_tool_call(_credential(ctx), params.name, arguments)
            )
        except types.MCPError:
            raise
        except Exception:
            raise types.MCPError(code=-32603, message=OPAQUE_FAULT) from None

    server = Server(
        "warden", on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )
    sub = server.streamable_http_app(
        streamable_http_path="/",
        stateless_http=True,
        host=config.host or "127.0.0.1",
        transport_security=TransportSecuritySettings(
            allowed_hosts=[config.host, f"{config.host}:*"] if config.host else None
        ),
    )
    app.router.routes.append(Mount(config.path, app=sub))
    app.state.mcp_session_manager = server.session_manager
```

- [ ] **Step 4: Wire it into `create_app` and the lifespan**

In `warden/broker/app.py`, add `mcp: "McpConfig | None" = None` to `create_app`'s keyword-only parameters, and after `app.state.spine = spine`:

```python
    if mcp is not None and mcp.enabled:
        # Imported here, not at module scope: the SDK is an optional extra,
        # and a deployment that never enables this surface must not need it
        # installed to start the broker.
        try:
            from warden.broker.mcp import mount_mcp
        except ImportError as exc:
            raise ConfigError(
                "[mcp].enabled is true but the MCP extra is not installed; "
                "install warden[mcp]"
            ) from exc

        mount_mcp(app, spine=spine, catalog=catalog, config=mcp)

        @contextlib.asynccontextmanager
        async def lifespan(_app):
            # A mounted sub-app's lifespan never runs, so the session
            # manager has to be started by the app it was mounted into.
            async with app.state.mcp_session_manager.run():
                yield

        app.router.lifespan_context = lifespan
```

Add `import contextlib` and `from warden.broker.config.loader import ConfigError, McpConfig` to `app.py`'s imports.

In `warden/broker/__main__.py`'s `build()`, pass `mcp=config.mcp` to `create_app(...)`.

- [ ] **Step 5: Run**

Run: `.venv/bin/pytest tests/warden/test_mcp_surface.py tests/warden/test_app.py -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add warden/broker/mcp.py warden/broker/app.py warden/broker/__main__.py tests/warden/test_mcp_surface.py tests/warden/test_app.py
git commit -m "feat: serve tools/call from the same spine the tool API uses"
```

---

### Task 12: `tools/list` over MCP, and the list-is-not-enforcement test

**Files:**
- Test: `tests/warden/test_mcp_surface.py` (append)

**Interfaces:**
- Consumes: `on_list_tools` from Task 11.
- Produces: nothing new — this task proves Task 11's listing behaves.

- [ ] **Step 1: Write the tests**

```python
def list_tools(client, token):
    import anyio
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    async def go():
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        async with streamable_http_client(
            "http://testserver/mcp",
            headers=headers,
            http_client=client_transport(client),
        ) as streams:
            async with Client(*streams) as session:
                return await session.list_tools()

    return anyio.run(go)


def test_listing_shows_only_what_the_token_grants(tmp_path):
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        _,
    ):
        result = list_tools(client, token_for(signer))
        names = sorted(t.name for t in result.tools)
        assert names == ["http_fetch", "query_customers", "read_document"]
        assert "send_email" not in names


def test_a_filtered_tool_is_still_refused_by_rule_when_called(tmp_path):
    """The filter is usability. Enforcement stays at tools/call, and a caller
    who names a tool the listing withheld gets a recorded refusal, not a
    404-shaped nothing."""
    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(
        tmp_path, signer, {"allow": False, "deny_reasons": ["tools.allowed"]}
    ) as (client, audit):
        result = call_tool(
            client,
            token_for(signer),
            "send_email",
            {"to": ["a@example.invalid"], "subject": "s", "body": "b"},
        )
        assert result.is_error is True
        assert "tools.allowed" in result.content[0].text
        assert [r["rule"] for r in audit.records()] == ["tools.allowed"]


def test_an_unauthenticated_listing_is_refused_and_recorded_over_mcp(tmp_path):
    import mcp as mcp_pkg

    from tests.warden.test_app import build_with_mcp
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        audit,
    ):
        with pytest.raises(mcp_pkg.types.MCPError):
            list_tools(client, None)
        records = audit.records()
        assert len(records) == 1
        assert records[0]["action"] == {"type": "tool_list"}
```

- [ ] **Step 2: Run**

Run: `.venv/bin/pytest tests/warden/test_mcp_surface.py -q`
Expected: all pass. If `test_an_unauthenticated_listing_...` records nothing, the SDK is rejecting before the handler runs — check that no `AuthSettings` or `TokenVerifier` was configured on the `Server`.

- [ ] **Step 3: Commit**

```bash
git add tests/warden/test_mcp_surface.py
git commit -m "test: listing is scoped to the token, and never the thing enforcing it"
```

---

### Task 13: Era parity and the catch-all

**Files:**
- Test: `tests/warden/test_mcp_surface.py` (append)

**Interfaces:**
- Consumes: `render_call`, the handler wrappers (Task 11).
- Produces: nothing new.

- [ ] **Step 1: Write the tests**

```python
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
def test_an_escaping_exception_renders_identically_at_both_eras(tmp_path, mode):
    """On 2026-07-28 an unhandled error is scrubbed to -32603. On the
    handshake era it is emitted as str(exc) -- so the same bug leaks the
    audit log's filesystem path to a model depending on what the client
    negotiated."""
    import anyio
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    from tests.warden.test_app import build_with_mcp, token_for
    from warden.broker.identity import Signer

    signer = Signer.generate()
    with build_with_mcp(tmp_path, signer, {"allow": True, "deny_reasons": []}) as (
        client,
        _,
    ):
        def explode(*a, **k):
            raise RuntimeError("/var/lib/warden/audit.jsonl is on fire")

        client.app.state.spine.handle_tool_call = explode

        async def go():
            async with streamable_http_client(
                "http://testserver/mcp",
                headers={"Authorization": f"Bearer {token_for(signer)}"},
                http_client=client_transport(client),
            ) as streams:
                async with Client(*streams, mode=mode) as session:
                    return await session.call_tool("read_document", {"doc_id": "a"})

        with pytest.raises(Exception) as caught:
            anyio.run(go)
        assert "on fire" not in str(caught.value)
        assert "audit.jsonl" not in str(caught.value)


def test_a_post_execute_fault_is_not_phrased_as_retryable(tmp_path):
    """The action already happened, the taint update did not, and the budget
    that would have stopped a second one never moved."""
    from warden.broker.mcp import AFTER_THE_FACT, render_call
    from warden.broker.spine import Kind, Outcome

    result = render_call(
        Outcome(kind=Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW, audit_seq=7)
    )
    assert result.is_error is True
    assert AFTER_THE_FACT in result.content[0].text
    assert "7" in result.content[0].text


def test_no_fault_rendering_carries_exception_text(tmp_path):
    from warden.broker.mcp import render_call
    from warden.broker.spine import Kind, Outcome

    secret = "postgres://user:pw@db.internal:5432"
    result = render_call(Outcome(kind=Kind.DESCRIBE_BACKEND_FAULT, message=secret))
    assert secret not in result.content[0].text
```

- [ ] **Step 2: Run**

Run: `.venv/bin/pytest tests/warden/test_mcp_surface.py -q`
Expected: all pass. If `mode=` is not a `Client` keyword in 2.0.0, drive the era by setting the `MCP-Protocol-Version` header explicitly and note it in the test docstring.

- [ ] **Step 3: Commit**

```bash
git add tests/warden/test_mcp_surface.py
git commit -m "test: the same fault renders identically at both protocol eras, and says nothing"
```

---

### Task 14: Surface parity and the concurrency mirror

The test the whole refactor rests on. It must not be a tautology: both surfaces are driven end to end against one app and one audit log, and the records are compared field by field.

**Files:**
- Create: `tests/warden/test_surface_parity.py`

**Interfaces:**
- Consumes: everything from Tasks 4, 11, 12.
- Produces: nothing.

- [ ] **Step 1: Write the parity test**

```python
"""Two front doors, one decision. Compared on the record, not on the code."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp", reason="requires the warden[mcp] extra")

VOLATILE = {"seq", "ts", "prev_hash", "hash"}

CASES = [
    ("allowed", {"allow": True, "deny_reasons": []}, "read_document", {"doc_id": "a"}),
    ("denied", {"allow": False, "deny_reasons": ["rows.bounded"]}, "read_document", {"doc_id": "a"}),
    ("capability", {"allow": False, "deny_reasons": ["tools.allowed"]}, "read_document", {"doc_id": "a"}),
    ("schema_invalid", {"allow": True, "deny_reasons": []}, "read_document", {}),
    ("unknown_tool", {"allow": True, "deny_reasons": []}, "no_such_tool", {"x": "y"}),
]


@pytest.mark.parametrize("name,payload,tool,args", CASES, ids=[c[0] for c in CASES])
def test_both_surfaces_write_the_same_record(tmp_path, name, payload, tool, args):
    from tests.warden.test_app import build_with_mcp, invoke, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)
    with build_with_mcp(tmp_path, signer, payload) as (client, audit):
        response = invoke(client, token, tool, args)
        try:
            call_tool(client, token, tool, args)
        except Exception:
            # A protocol error is a legitimate rendering for some variants;
            # the record it wrote is what this test is about.
            pass

        records = audit.records()
        assert len(records) == 2, f"{name}: {records}"
        http, mcp = records
        stripped = [
            {k: v for k, v in r.items() if k not in VOLATILE} for r in (http, mcp)
        ]
        assert stripped[0] == stripped[1]


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
        after_http = spine.snapshot_for_test("4711")["rows_returned_so_far"]
        call_tool(client, token, "query_customers", {"filter": "id=8812"})
        after_mcp = spine.snapshot_for_test("4711")["rows_returned_so_far"]
        assert after_http == 1
        assert after_mcp == 2
```

Add to `Spine` in `warden/broker/spine.py`:

```python
    def snapshot_for_test(self, task_id: str) -> dict:
        """The task's accumulated state. Named for its only caller: nothing
        in the serving path reads state except through handle_tool_call."""
        return self._taint.snapshot(task_id)
```

- [ ] **Step 2: Write the concurrency mirror**

Append to `tests/warden/test_surface_parity.py`:

```python
async def test_concurrent_mcp_calls_for_one_task_do_not_exceed_the_row_bound(tmp_path):
    """The mirror of test_app.py's own concurrency test, through the other
    door. The invariant is that the spine contains no await, so a snapshot
    and the read it authorises cannot be interleaved. A handler registered as
    a plain `def` would run on a worker thread and break it -- which is a
    one-word change away at all times."""
    import anyio

    from tests.warden.test_app import build_with_mcp, token_for
    from tests.warden.test_mcp_surface import call_tool
    from warden.broker.identity import Signer

    signer = Signer.generate()
    token = token_for(signer)

    import httpx

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
        handler = getattr(server, "_on_call_tool", None) or getattr(
            server, "on_call_tool", None
        )
        assert handler is not None, "could not reach the registered handler"
        assert inspect.iscoroutinefunction(handler)
```

> If the session manager does not expose the handler, reach it through the `Server` instance instead — store it on `app.state.mcp_server` in `mount_mcp` and assert against that.

- [ ] **Step 3: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: everything passes except the 21 pre-existing OPA errors.

- [ ] **Step 4: Commit**

```bash
git add tests/warden/test_surface_parity.py warden/broker/spine.py
git commit -m "test: both doors write the same record, and neither can race the budget"
```

---

### Task 15: The stdio shim

**Files:**
- Create: `warden/cli/mcp_shim.py`
- Modify: `warden/cli/main.py`
- Test: `tests/warden/test_mcp_shim.py`

**Interfaces:**
- Consumes: the mounted surface (Task 11).
- Produces: `warden mcp --broker URL --token-file PATH [--allow-http]`; `run_shim(broker: str, token_file: Path, allow_http: bool) -> int`.

- [ ] **Step 1: Write the failing tests**

Create `tests/warden/test_mcp_shim.py`:

```python
"""The shim runs inside an untrusted agent's process tree. It holds one
token, and every rule here exists because something else would take it."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp", reason="requires the warden[mcp] extra")

from warden.cli.mcp_shim import TokenFileAuth, build_upstream_client, validate_broker


def test_the_upstream_client_ignores_proxy_environment(monkeypatch):
    """The shim is a child of the agent, and rung 0 tells operators to export
    HTTP_PROXY pointed at warden's own egress proxy. Inheriting it sends the
    shim's POST to :3128 in absolute form, where the proxy 405s every
    non-CONNECT method -- so the shim never reaches the broker at all, and
    every attempt is audited as an egress probe."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    client = build_upstream_client("https://broker.internal")
    assert client.trust_env is False


def test_redirects_are_not_followed():
    """A 3xx relocates the Authorization header to another origin, and under
    renewal that token is refreshed on a timer -- a durable capability rather
    than a five-minute leak."""
    client = build_upstream_client("https://broker.internal")
    assert client.follow_redirects is False


def test_plain_http_is_refused_without_an_explicit_opt_in():
    with pytest.raises(ValueError, match="https"):
        validate_broker("http://broker.internal", allow_http=False)
    assert validate_broker("http://127.0.0.1:8080", allow_http=True)
    assert validate_broker("https://broker.internal", allow_http=False)


def test_the_token_is_read_per_request_not_captured_once(tmp_path):
    """A Client captures headers at construction, so a token file that is
    rewritten later would never be picked up -- and that only breaks once
    renewal exists, as 'the session dies at the first refresh'."""
    token_file = tmp_path / "token"
    token_file.write_text("first")
    auth = TokenFileAuth(token_file)

    class Req:
        def __init__(self):
            self.headers = {}

    a = Req()
    next(auth.auth_flow(a))
    assert a.headers["Authorization"] == "Bearer first"

    token_file.write_text("second")
    b = Req()
    next(auth.auth_flow(b))
    assert b.headers["Authorization"] == "Bearer second"


def test_a_world_readable_token_file_is_refused(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("t")
    token_file.chmod(0o644)
    with pytest.raises(PermissionError, match="0600"):
        TokenFileAuth(token_file).read()
```

- [ ] **Step 2: Run — expect an import error**

Run: `.venv/bin/pytest tests/warden/test_mcp_shim.py -q`
Expected: FAIL, `ModuleNotFoundError: warden.cli.mcp_shim`.

- [ ] **Step 3: Write the shim**

Create `warden/cli/mcp_shim.py`:

```python
"""A stdio front end that forwards to a broker's MCP surface.

This process runs inside the agent's own process tree, launched by whatever
config the agent reads. Treat it as untrusted: it holds one task token, it
holds no key, it knows no control-plane address, and it makes no decision.
Everything it could be tricked into doing has a rule below.

It contains no policy and no catalog. Every question it is asked is asked
again upstream, which is what keeps it from becoming a second place where a
call could be interpreted.
"""

from __future__ import annotations

import stat
from pathlib import Path
from urllib.parse import urlparse

import httpx2


class TokenFileAuth(httpx2.Auth):
    """Reads the token per request rather than capturing it once.

    A client captures its headers at construction, so a token that is
    replaced on disk mid-session would never reach the wire. Reading a small
    local file before a network round-trip costs nothing next to the round
    trip it precedes.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def read(self) -> str:
        mode = self._path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(
                f"{self._path} is group- or world-accessible; it must be 0600"
            )
        return self._path.read_text(encoding="utf-8").strip()

    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self.read()}"
        yield request


def validate_broker(url: str, *, allow_http: bool = False) -> str:
    scheme = urlparse(url).scheme
    if scheme == "https":
        return url
    if scheme == "http" and allow_http:
        return url
    raise ValueError(
        f"--broker must be https (got {scheme!r}); pass --allow-http for "
        f"loopback development"
    )


def build_upstream_client(broker: str) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        base_url=broker,
        # The agent that launched this process is told to export proxy
        # variables pointing at warden's own egress proxy. Honouring them
        # here sends this client's POST to that proxy in absolute form,
        # where a non-CONNECT method is refused and recorded -- so the shim
        # would never reach the broker, and would fill the audit log with
        # egress probes on the way.
        trust_env=False,
        # A 3xx would move the Authorization header to whatever origin the
        # response named.
        follow_redirects=False,
        timeout=60.0,
    )


def _strip_server_info(result):
    """The upstream's own identity travels in list results' metadata. It is
    the broker's, not this shim's, and nothing downstream needs it."""
    meta = getattr(result, "meta", None)
    if isinstance(meta, dict):
        meta.pop("io.modelcontextprotocol/serverInfo", None)
    return result


def run_shim(broker: str, token_file: Path, *, allow_http: bool = False) -> int:
    import anyio
    from mcp import Client, types
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server

    validate_broker(broker, allow_http=allow_http)
    auth = TokenFileAuth(token_file)

    async def main() -> None:
        client = build_upstream_client(broker)
        client.auth = auth
        async with streamable_http_client(
            broker, http_client=client, cache=None
        ) as streams:
            async with Client(*streams) as upstream:

                async def on_list_tools(ctx, params):
                    return _strip_server_info(await upstream.list_tools())

                async def on_call_tool(ctx, params):
                    return await upstream.call_tool(
                        params.name, params.arguments or {}
                    )

                server = Server(
                    "warden-shim",
                    on_list_tools=on_list_tools,
                    on_call_tool=on_call_tool,
                )
                async with stdio_server() as (read, write):
                    await server.run(
                        read, write, server.create_initialization_options()
                    )

    anyio.run(main)
    return 0
```

> **If `streamable_http_client` rejects `cache=None`**, use whatever the 2.0.0 signature calls the response-cache control (`cache_mode="no-store"` was the other candidate) and record the real name in the module docstring. Caching must be off: `ListToolsResult` is a `CacheableResult`, and a cached listing defeats per-token filtering.

- [ ] **Step 4: Register the subcommand**

In `warden/cli/main.py`, add the handler:

```python
def _cmd_mcp(args: argparse.Namespace) -> int:
    from warden.cli.mcp_shim import run_shim

    try:
        return run_shim(
            args.broker, Path(args.token_file), allow_http=args.allow_http
        )
    except (ValueError, PermissionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
```

and in `build_parser()`, after `p_config`:

```python
    p_mcp = sub.add_parser(
        "mcp", help="stdio MCP shim: forwards a local agent to a broker's MCP surface"
    )
    p_mcp.add_argument("--broker", required=True, help="base URL of the MCP surface")
    p_mcp.add_argument(
        "--token-file",
        required=True,
        help="path to the task token, re-read before each forwarded request",
    )
    p_mcp.add_argument(
        "--allow-http", action="store_true", help="permit a plain-http broker URL"
    )
    p_mcp.set_defaults(func=_cmd_mcp)
```

- [ ] **Step 5: Run**

Run: `.venv/bin/pytest tests/warden/test_mcp_shim.py tests/warden/test_entry_points.py -q`
Then: `.venv/bin/warden mcp --help`
Expected: tests pass; `--help` exits 0.

- [ ] **Step 6: Commit**

```bash
git add warden/cli/mcp_shim.py warden/cli/main.py tests/warden/test_mcp_shim.py
git commit -m "feat: a stdio shim that holds one token and can be pointed nowhere else"
```

---

### Task 16: Documentation

**Files:**
- Modify: `README.md`, `docs/DEPLOYMENT.md`, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`, `warden/reference/README.md`

**Interfaces:**
- Consumes: everything.
- Produces: nothing.

- [ ] **Step 1: Update the limitation the README states**

In `README.md`'s "Known limitations", replace the "The tool API needs an agent you can point at it" bullet's closing sentence with a statement that the MCP surface now exists, is off by default, and does not contain a local agent. Keep the bullet — the limitation is narrowed, not removed.

- [ ] **Step 2: Add the three threat-model entries**

In `docs/THREAT_MODEL.md`, add:

- **The front door contains nothing.** An agent reached over MCP can hold other MCP servers warden has never heard of. Containment is the network layout.
- **The local path is uncontained.** A local agent has a route to the control plane, which authenticates nobody.
- **Rule names in denials are an enumeration oracle.** `DENY_PRECEDENCE` is ordered so each rule is a positive assertion, denied calls consume no budget, and nothing rate-limits them. A per-task denial counter makes a search visible in replay; a cap is future work.

- [ ] **Step 3: Document deployment**

In `docs/DEPLOYMENT.md`, add the `[mcp]` section's keys, the `warden[mcp]` extra, and `warden config check --mcp` to the tables. Add to "Required": run `config check --mcp` before enabling the surface.

- [ ] **Step 4: Mark P1 done in the roadmap**

In `docs/ROADMAP.md`, note that rung 1 has shipped and that `❌ Production` does not move — Phase 3 still gates it.

- [ ] **Step 5: Run the docs test and the full suite**

Run: `.venv/bin/pytest -q`
Expected: `tests/test_docs_are_current.py` passes — check no new text contains `python -m broker`, a bare `policies/authz.rego`, or any other banned needle.

- [ ] **Step 6: Commit**

```bash
git add README.md docs/
git commit -m "docs: state what the front door does, and what it does not contain"
```

---

## Self-Review

**Spec coverage.** Spec §1 (dependency) → Task 10. §2 (spine) → Tasks 3, 4, 5. §3 (MCP surface) → Tasks 11, 12, 13. §4 (shim) → Task 15. §5 (config) → Tasks 6, 7, 8, 9. §6 (test plan) → every task, with the parity and concurrency tests in Task 14. §7 (threat model) → Task 16. §8 (build constraints) → Global Constraints. The two pulled-in items are Tasks 1 and 2.

**One spec item is deliberately not implemented as written:** the per-task denial counter named in §7. It needs a field on `TaintTracker` and a decision about whether it enters the policy input, which touches the state object P3 replaces wholesale. Task 16 documents the oracle; the counter should be planned with P3 rather than built twice. Raise this before starting if you disagree.

**Placeholders.** None. Every code step carries the code. Three steps carry a conditional fallback (the ASGI transport in Task 11, the cache keyword in Task 15, the handler accessor in Task 14) — each names the exact alternative and requires recording which was used, because the SDK's 2.0.0 signatures were read from published sources rather than exercised here.

**Type consistency.** `Kind`, `Outcome`, `ListOutcome`, `Spine`, `DENIED`/`AUDIT_UNAVAILABLE`/`FAULT` are defined in Task 4 and used with those names in Tasks 5, 11, 13, 14. `json_schema` is defined in Task 7 and called in Tasks 9 and 11. `McpConfig(enabled, path, host)` is defined in Task 8 and consumed in Tasks 11 and 14's builder. `CatalogEntry.description`/`.title` are added in Task 6 and read in Tasks 9 and 11. `check_catalog(..., *, opa_url=None, mcp_enabled=False)` is keyword-only throughout. `snapshot_for_test` is added in Task 14 and used only there.
