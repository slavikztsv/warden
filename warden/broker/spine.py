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
            # Shape-checked here, BEFORE describe() is ever called, so
            # describe() (which decides what gets audited and policy-checked)
            # and execute() (which acts) are guaranteed to interpret the same
            # args the same way. Skipping this check lets the two stages
            # disagree about what the target even is -- e.g. a bare string
            # passed where a schema expects a list gets read
            # character-by-character by one stage and as the original whole
            # string by the other, so the decision and the action would be
            # judging two different things.
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
