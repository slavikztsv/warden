"""The decision sequence, as a value rather than a response.

verify -> validate -> describe -> charge -> decide -> record -> execute.
Nothing here
knows about HTTP or any wire protocol: it returns an Outcome, and a surface
renders it. That is what stops two front doors onto one broker from
disagreeing about what a call was.

The sequence is SYNCHRONOUS, and it used to be the thing that made the row
budget safe: between reading task state and recording what a call read,
nothing could suspend, so two calls for one task could not both read the same
starting budget and both pass. That was a property of the call graph rather
than of the state, and A6 (an async spine) and a second worker each dissolve
it.

It is no longer load-bearing. A call now CHARGES its estimate through
TaskStateStore before the decision, and the store's own atomicity is what
orders concurrent callers -- see warden/broker/taint.py. The synchrony here
is a fact about today's implementation, not a control, and A6 may remove it
without removing anything that protects the budget.

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

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from warden.broker.adapters.base import ToolResult, ToolTarget, UnknownTool
from warden.broker.identity import TaskToken, TokenInvalid
from warden.broker.record_fields import args_digest, empty_task_state
from warden.broker.taint import TaskStateStore

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
    # Named for WHETHER THE ACTION HAPPENED, not for which store method
    # failed, because that is exactly what decides the rendering. The first
    # covers both peek and charge, and every path it covers has acted on
    # nothing.
    STATE_UNAVAILABLE_BEFORE_EXECUTE = "state_unavailable_before_execute"
    STATE_UNAVAILABLE_AFTER_EXECUTE = "state_unavailable_after_execute"


DENIED = frozenset({
    Kind.POLICY_DENIED,
    Kind.UNKNOWN_TOOL_DENIED,
    Kind.MALFORMED_BODY_DENIED,
    Kind.SCHEMA_INVALID_DENIED,
    Kind.DESCRIBE_CLIENT_ERROR_DENIED,
})

# "This broker could not make a durable enough record, or could not read the
# state a decision needs, so it refused." Every member acted on nothing.
# STATE_UNAVAILABLE_BEFORE_EXECUTE joins them rather than getting a status of
# its own: to a caller the situation is identical -- a dependency the
# enforcement point needs is unreachable, nothing happened, try later.
AUDIT_UNAVAILABLE = frozenset({
    Kind.AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED,
    Kind.AUDIT_UNAVAILABLE_ON_ALLOW,
    Kind.AUDIT_UNAVAILABLE_ON_DENY,
    Kind.STATE_UNAVAILABLE_BEFORE_EXECUTE,
})

# Three faults with three different audit consequences, kept apart on
# purpose. DESCRIBE_BACKEND_FAULT wrote nothing at all; the other two each
# left exactly one durable allow record for an action that may have already
# happened. A surface that collapses them cannot tell a caller which.
FAULT = frozenset({
    Kind.DESCRIBE_BACKEND_FAULT,
    Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW,
    Kind.TAINT_REJECTED_AFTER_EXECUTE,
    Kind.STATE_UNAVAILABLE_AFTER_EXECUTE,
})


# `args_digest` and `empty_task_state` live in record_fields.py now. They are
# shared with warden/broker/control.py, which cannot import THIS module:
# measured, reaching spine.py takes the control plane's import graph from 7
# warden modules to 13 -- taint and adapters.base included -- in the one
# process that holds the private signing key. record_fields.py imports
# nothing but the standard library, and the graph stays at 9. Importing them
# by name above keeps every existing `from warden.broker.spine import
# args_digest` working.


@dataclass(frozen=True)
class Outcome:
    kind: Kind
    rule: str = ""
    result: ToolResult | None = None
    message: str = ""
    # The seq of the durable allow record. Three variants carry it: EXECUTED
    # (the allow that went on to succeed) and the two that fire after the
    # same allow was written but something downstream still failed
    # (EXECUTE_FAILED_AFTER_DURABLE_ALLOW, TAINT_REJECTED_AFTER_EXECUTE). A
    # caller that must not retry needs a handle on the thing that already
    # happened.
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
        task_state: TaskStateStore,
        audit,
        catalog,
        policy_digest: str,
        clock: Callable[[], int],
        state_grace_seconds: int = 3600,
    ) -> None:
        self._verifier = verifier
        self._pdp = pdp
        self._state = task_state
        self._audit = audit
        self._catalog = catalog
        self._digest = policy_digest
        # Injected rather than read from a module-level clock at call time.
        # Patching a module global only ever covers the one module that
        # reads it, and this sequence is shared by every front door mounted
        # on the broker -- each of which would need its own patch point.
        # One clock, every surface, one patch point.
        self._clock = clock
        # How long a task's whole state outlives the expiry of the last token
        # that touched it. Held here rather than in the store because it is a
        # fact about tokens, not about storage; the store's own
        # max_in_flight_seconds is the opposite -- a recovery mechanism with
        # no token in it.
        self._state_grace = state_grace_seconds

    def _authenticate(self, credential: str | None):
        if credential is None:
            return None, "Bearer token required."
        try:
            return self._verifier.verify(credential, now=self._clock()), ""
        except TokenInvalid as exc:
            return None, str(exc)

    def authenticate(self, credential: str | None, tool: str) -> TaskToken | Outcome:
        """Verifies a credential and, on failure, writes the sentinel
        refusal record right here.

        Exists so a route can call this FIRST -- before it reads anything
        else about the request, in particular the body -- and stop the
        instant it gets an Outcome back. handle_tool_call() below does NOT
        accept the TaskToken this returns; it re-verifies the same
        credential from scratch (an Ed25519 verify is cheap). That is
        deliberate, not redundant: a route calls this, then awaits the body
        across a suspension point, then calls handle_tool_call(), and a
        credential that goes stale in that window must still be caught.

        The two verifies cannot double-write a sentinel record for the same
        refusal, because they cover disjoint cases. If THIS call refuses,
        the route stops here and handle_tool_call() never runs -- one
        write. If this call succeeds, nothing is written here at all, so
        handle_tool_call()'s own refusal (if the credential expires before
        it re-checks) is the first and only record for that failure -- also
        one write. Either way, exactly one record per refused request.
        """
        token, message = self._authenticate(credential)
        if token is None:
            return self._refuse({"type": "tool_call", "tool": tool}, message, Outcome)
        return token

    def handle_tool_call(
        self, credential: str | None, tool: str, args: dict | None
    ) -> Outcome:
        token, message = self._authenticate(credential)
        if token is None:
            return self._refuse(
                {"type": "tool_call", "tool": tool}, message, Outcome
            )

        # One clock read for the whole call. Every store operation below --
        # the charge, whatever settles it, any peek -- must agree about what
        # "now" is, or a call could prune the very reservation it just took.
        now = self._clock()

        if args is None:
            # A body that did not parse. Audited against the literal empty
            # dict, because there are no arguments to digest.
            return self._deny_before_charge(
                token, tool, {}, ToolTarget(kind="malformed"), now,
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
            return self._deny_before_charge(
                token, tool, args, ToolTarget(kind="malformed"), now,
                MALFORMED, Kind.SCHEMA_INVALID_DENIED,
            )

        try:
            target = self._catalog.describe(tool, args)
            # Fetched HERE, inside describe()'s own guard, and deliberately
            # not down beside the charge. Both are questions put to the
            # catalog about a call that has not happened yet, and both fail
            # the same way: a catalog or adapter defect is a server bug, so
            # the bare `except Exception` below reports it as a fault that
            # acted on nothing. Asking for it inside the store's try/except
            # instead would report an adapter with no data_class as "the
            # state store is unreachable, try again later" -- a diagnosis
            # that sends an operator to the wrong system, and a 503 that
            # invites a retry of a call that will fail identically forever.
            data_class = self._catalog.data_class(tool)
        except UnknownTool:
            # Order matters: UnknownTool is a plain Exception subclass, so
            # this clause must stay above both of the ones below.
            return self._deny_before_charge(
                token, tool, args, ToolTarget(kind="unknown"), now,
                CAPABILITY, Kind.UNKNOWN_TOOL_DENIED,
            )
        except (ValueError, KeyError, TypeError, IndexError):
            # Client-caused failures the schema did not catch. The tuple is
            # exactly these four and was widened on purpose: KeyError is not
            # a ValueError, and sending it to the branch below produced a
            # fault with no record -- an agent probing with no trace.
            return self._deny_before_charge(
                token, tool, args, ToolTarget(kind="malformed"), now,
                MALFORMED, Kind.DESCRIBE_CLIENT_ERROR_DENIED,
            )
        except Exception as exc:
            # A server bug, not the agent's doing. No decision was avoided
            # because of anything the caller did, so nothing is recorded
            # against it.
            return Outcome(kind=Kind.DESCRIBE_BACKEND_FAULT, message=str(exc))

        # Charged BEFORE the decision, because the decision has to price this
        # call against everything else in flight for the same task. What comes
        # back is the state as it was BEFORE this charge, and that is what
        # feeds both the policy input and the audit record -- which is also
        # why a task's first PII read cannot deny itself under
        # egress.pii_sink.
        #
        # This does not weaken "the decision is written down before anything
        # happens". A reservation is bookkeeping: invisible to the world
        # except as strictness against this task's own budget, and released
        # on every path below that does not act.
        charge_id = uuid.uuid4().hex
        try:
            state = self._state.charge(
                token.task_id,
                charge_id=charge_id,
                rows=target.estimated_rows,
                data_class=data_class,
                now=now,
                expires_at=token.exp + self._state_grace,
            )
        except Exception as exc:
            # Nothing has happened, so nothing is recorded -- the same reason
            # DESCRIBE_BACKEND_FAULT records nothing. A store this process
            # cannot reach is not the agent's doing, and a broker that cannot
            # read the state a decision needs must refuse rather than guess.
            return Outcome(
                kind=Kind.STATE_UNAVAILABLE_BEFORE_EXECUTE, message=str(exc)
            )

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
            # Rows AND class: nothing ran and nothing was read, so a refused
            # call must leave no trace in task state. Keeping the class here
            # would let one denied PII read poison a task for the rest of its
            # life, which an agent could trip deliberately.
            self._settle(self._state.release, token.task_id, charge_id, now)
            return self._deny(
                token, tool, args, target, state, decision.rule, Kind.POLICY_DENIED
            )

        try:
            record = self._append(
                token, tool, args_digest(args), target, state, "allow", decision.rule
            )
        except OSError as exc:
            # If it cannot be logged, it cannot be done. execute() must not
            # run below, so the reservation is released rather than abandoned.
            self._settle(self._state.release, token.task_id, charge_id, now)
            return Outcome(kind=Kind.AUDIT_UNAVAILABLE_ON_ALLOW, message=str(exc))

        try:
            result = self._catalog.execute(tool, args)
        except Exception as exc:
            # Deliberately broad. The allow above is durable, so nothing may
            # escape this call site or the log asserts an authorised action
            # while a caller sees a bare crash. No second record is written:
            # the allow stands as the account of what was authorised.
            #
            # abandon, not release, and the asymmetry is the point: the
            # adapter reached the source and may have received bytes before
            # failing, so the taint stands, while the budget does not pay for
            # a backend outage.
            self._settle(
                self._state.abandon, token.task_id, charge_id, now,
                data_class=data_class,
            )
            return Outcome(
                kind=Kind.EXECUTE_FAILED_AFTER_DURABLE_ALLOW,
                message=str(exc),
                audit_seq=record["seq"],
            )

        # A negative count is an adapter defect. It now costs what was
        # AUTHORISED rather than costing nothing, which is what leaving the
        # state untouched used to mean: the reservation is settled at the
        # estimate, and the caller is told, exactly as before.
        rejected = result.rows < 0
        try:
            self._state.reconcile(
                token.task_id,
                charge_id,
                rows=target.estimated_rows if rejected else result.rows,
                data_class=result.data_class,
                now=now,
            )
        except Exception as exc:
            return Outcome(
                kind=Kind.STATE_UNAVAILABLE_AFTER_EXECUTE,
                message=str(exc),
                audit_seq=record["seq"],
            )

        if rejected:
            return Outcome(
                kind=Kind.TAINT_REJECTED_AFTER_EXECUTE,
                message=f"rows must be non-negative, got {result.rows}",
                audit_seq=record["seq"],
            )

        return Outcome(
            kind=Kind.EXECUTED,
            rule=decision.rule,
            result=result,
            audit_seq=record["seq"],
        )

    def task_state(self, task_id: str) -> dict:
        """What this task has accumulated: rows read, data classes held.

        A read-only view for anything that needs to see the budget without
        spending it -- a diagnostic, an operator question, a test. Deliberately
        NOT named for tests: a production class carrying a test-only method
        invites a caller who should not have one, and this accessor is
        legitimate on its own terms. The serving path still reads state only
        through handle_tool_call, which snapshots it once per call.

        Reads through the store's `peek`, which is the only method on it that
        creates nothing. This accessor takes an ARBITRARY string from a caller
        with no minted token behind it at all -- an operator, a diagnostic --
        so a read that planted an entry would leak one per id it is ever asked
        about, for the life of the process. `peek` returns the same shape
        `charge` does without creating anything, which is what makes
        "read-only" here a fact about the code rather than a claim in a
        docstring.

        What it reports is the CHARGED total: rows settled plus rows reserved
        by calls still in flight. An operator watching this during concurrent
        activity will see it move up and back down, and that is the number
        policy is judging, not an artefact.
        """
        return self._state.peek(task_id, now=self._clock())

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

    def record_handshake_refusal(self, rule: str) -> None:
        """Records a refusal for a call that never reached authentication --
        or any of this spine's other methods -- at all.

        Called from warden/broker/mcp.py's `_EraGate`, which wraps the MCP
        surface's mounted sub-app and runs BEFORE the SDK's own routing:
        every request whose `MCP-Protocol-Version` is absent, duplicated, or
        names anything other than the one revision this server serves --
        a handshake-era release, an unserved future revision, or outright
        garbage -- is refused right there, without ever reaching
        `authenticate`, `handle_tool_call`, or `list_tools` above. There is
        no token and no parsed body at that point -- not even an unverified
        one -- so the record carries the same sentinel principal fields
        `_refuse` uses, and an action shaped for what this is: a refusal of
        the transport handshake itself, not of any named tool.

        This lets a caller presenting no credential at all drive a write to
        the audit log, exactly as broker/proxy.py's refusal for a
        non-CONNECT probe does. That is the deliberate trade, not an
        oversight: the alternative is the vector this method exists to
        close, where an unrecorded refusal let a caller probe the
        enforcement point indefinitely by adding one header, and a
        forgeable audit row is a smaller cost than a probe that leaves no
        trace of ever having happened.

        Best-effort, unlike `_refuse`: there is no Outcome for this to
        return -- the gate runs in raw ASGI, before any handler exists that
        could render one -- so there is no channel to report an unavailable
        log through. Matches broker/proxy.py's own `_audit_refusal`, which
        the same asymmetry (documented in docs/THREAT_MODEL.md) applies to:
        the refusal itself is not optional, but logging it is best-effort on
        top of that, so a write failure here is swallowed and the caller is
        still refused.
        """
        try:
            self._audit.append(
                task_id="-",
                agent_id=UNAUTHENTICATED,
                purpose="-",
                action={"type": "mcp_handshake"},
                target=ToolTarget(kind="unknown").as_dict(),
                args_digest="sha256:none",
                decision="deny",
                rule=rule,
                task_state=empty_task_state(),
                policy_bundle_digest=self._digest,
            )
        except OSError:
            pass

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
                task_state=empty_task_state(),
                policy_bundle_digest=self._digest,
            )
        except OSError as exc:
            # Same rule as every other refusal this spine writes: if it
            # cannot be logged, it is reported as unavailable rather than
            # quietly refused. (broker/proxy.py deliberately differs -- it
            # swallows the failure and still refuses -- because a tunnel
            # refusal must happen even when it cannot be recorded. The
            # asymmetry is documented in docs/THREAT_MODEL.md.)
            return factory(
                kind=Kind.AUDIT_UNAVAILABLE_ON_UNAUTHENTICATED, message=str(exc)
            )
        return factory(kind=Kind.UNAUTHENTICATED, message=message)

    def _settle(self, operation, task_id: str, charge_id: str, now: int, **extra) -> None:
        """Release or abandon a charge, swallowing a store failure.

        Deliberately unlike the charge itself, which refuses. A settle that
        cannot be written leaves a reservation behind, and a reservation's
        deadline already collects one -- so failing the call here would turn a
        bounded, self-healing over-charge into an error the caller can do
        nothing with, on a path where the outcome has already been decided.
        """
        try:
            operation(task_id, charge_id, now=now, **extra)
        except Exception:
            pass

    def _deny_before_charge(
        self, token, tool, args, target, now, rule, kind
    ) -> Outcome:
        """A denial reached before there was an estimate to charge.

        Reads task state at the point of denial rather than up front. The
        invariant the old single snapshot protected -- the decision and the
        record must never see different state -- is preserved and narrowed:
        on the charge path there is exactly one read, `charge`'s return,
        feeding both. Here there is no decision at all, only a record, so one
        `peek` is the whole of it. No path reads task state twice.
        """
        try:
            state = self._state.peek(token.task_id, now=now)
        except Exception as exc:
            return Outcome(
                kind=Kind.STATE_UNAVAILABLE_BEFORE_EXECUTE, message=str(exc)
            )
        return self._deny(token, tool, args, target, state, rule, kind)

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
