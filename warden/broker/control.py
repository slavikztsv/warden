"""Control plane: the only place tokens are minted, and now the only place
that records what was minted.

This route has no caller authentication, and it lets its caller choose
task_id, purpose, allowed_tools and counterparties -- i.e. anyone who can
reach it holds unlimited authority over this system, including the ability to
reset a task's taint state and row budget by naming a fresh task_id. The
control that makes that acceptable is entirely topological: it is served by
broker/control_main.py as its own service (`broker-control`), attached to
`backend-net` only and never to `agent-net`, so no route exists from the agent
to this listener.

Co-hosting it in the broker process, as an earlier version did, made that
claim false: the broker is attached to agent-net by necessity, so binding the
control app to 0.0.0.0:8081 inside it put an unauthenticated minting endpoint
one hop from the agent. Keep this app out of any process the agent can reach.

B7 added the record. It does not narrow anything above -- a caller who can
reach this endpoint can still mint whatever it likes -- but the log now says
what they minted, which is the question the audit chain could not answer:
every refusal in it was measured against a grant the log had never seen.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from warden.broker.audit import AuditLog
from warden.broker.identity import Signer, TaskToken, Verifier
from warden.broker.record_fields import args_digest, empty_task_state

# What a caller is told when the grant could not be recorded. A fixed string,
# never `str(exc)`: AuditLog's own OSError names the audit path verbatim
# ("audit log /data/audit.jsonl is held by another writer"), and leaking that
# to a caller is a defect this repo has already had and fixed once -- see
# broker/refusals.py, which exists because the HTTP door emitted the audit
# path in a 503 for a whole task after the MCP door had stopped.
#
# Here rather than in refusals.py, for two reasons. That module's own
# docstring scopes it: "Two front doors render the same Outcome -- app.py over
# HTTP, mcp.py over MCP ... A surface that owned its own copy would be free to
# keep leaking after the other stopped." It exists because TWO surfaces shared
# one message and drifted; there is one control plane, one surface, one
# message. And importing it costs `from warden.broker.spine import FAULT,
# Kind` -- measured, that takes this process's warden import graph from 7
# modules to 13, pulling taint and adapters.base into the one process that
# holds the private signing key. It is 9 as built.
MINT_UNAVAILABLE_MESSAGE = (
    "The control plane cannot record what it grants, so it is not granting "
    "anything. No token was issued."
)


class TokenRequest(BaseModel):
    agent_id: str
    task_id: str
    purpose: str
    allowed_tools: list[str]
    data_classes: list[str]
    counterparties: list[str]


def record_mint(audit: AuditLog, *, token: TaskToken, request_digest: str) -> dict:
    """Writes the grant into the same hash chain the decisions go into.

    Takes the VERIFIED TaskToken rather than the request, and that is the
    whole reason the route verifies what it just signed. The record then
    states what the TOKEN says, not what the caller asked for. If those two
    ever diverge -- a mint() that drops a field, a claim that resolves
    differently than the config implies -- the record follows the artifact the
    broker will actually enforce against. A record built from the request
    would describe an authority that was never issued. It is also the only way
    to get `jti` and `exp` at all: both are generated inside mint() and are
    not otherwise visible to the caller.

    Thirteen fields, the same thirteen every decision record carries, so zero
    interfaces change and the record shape ROADMAP F3 names stays one shape.
    The grant goes in `target` because `target` already means "the thing this
    action is about" -- for a tool call a document, a query, a host, a
    recipient; for a mint, the authority granted.

    The TOKEN ITSELF IS NEVER RECORDED. `jti` and `exp` identify a grant; the
    JWT is a bearer credential, and `warden replay` prints what it is given.

    Two of the thirteen are sentinels, and both are honest about being one:

      * policy_bundle_digest is "none". broker-control mounts no /policies at
        all, and stamping the digest of a bundle it never evaluated would
        claim the mint was decided under it. Not "sha256:none" -- args_digest
        wears its field's prefix because arguments conceptually existed and
        were deliberately not read, whereas here the bundle does not exist,
        and a sha256:-prefixed value in a digest field reads like a digest.
      * task_state is the MINTER'S view, not the task's. See
        record_fields.empty_task_state, which says why, and note that a
        renewal minted against a task that already holds pii still records
        [] and 0. The shape is forced: warden/cli/replay.py subscripts
        task_state["data_classes_held"] for every record before printing
        anything, so {} or "-" tracebacks the one tool that renders the log,
        and does so AFTER verify-chain has reported it intact.

    rule is "mint.unconditional" rather than "allow". Writing "allow" renders
    a cleaner line (replay.py suppresses the rule only when it is literally
    that string) and would assert that a policy rule named `allow` fired.
    Nothing evaluated this mint: the route authenticates nobody and loads no
    policy, which is a documented boundary in docs/THREAT_MODEL.md and not an
    oversight. When C2 gives the control plane a policy this becomes a real
    rule name, and the change is visible in the log.

    `action` carries no `tool` key -- there is one fact here, and it is the
    type. Same shape as the spine's `tool_list` and `mcp_handshake`, rather
    than the proxy's `{"type": "egress", "tool": "CONNECT"}`, which names a
    layer AND a method.
    """
    return audit.append(
        task_id=token.task_id,
        agent_id=token.agent_id,
        purpose=token.purpose,
        action={"type": "mint"},
        target={
            "kind": "token",
            "allowed_tools": list(token.allowed_tools),
            "data_classes": list(token.data_classes),
            "counterparties": list(token.counterparties),
            # Always None today. Carried anyway: it is part of the token,
            # delegation is a live roadmap item, and a field added later is a
            # record shape that changed.
            "delegated_from": token.delegated_from,
            "jti": token.jti,
            "exp": token.exp,
        },
        args_digest=request_digest,
        decision="allow",
        rule="mint.unconditional",
        task_state=empty_task_state(),
        policy_bundle_digest="none",
    )


def create_control_app(*, signer: Signer, audit: AuditLog, issuer: str) -> FastAPI:
    """Builds the minting app.

    `issuer` is a parameter rather than something read off the signer because
    Signer keeps its own privately and exposes no accessor -- so a Verifier
    built from `signer.public_key_pem()` alone would get identity.py's module
    default, and every deployment that configures a different issuer would
    500 on its first mint. That is not hypothetical: tests/warden/
    test_key_split.py builds exactly that deployment and asserts 200.

    Note what this self-verify does NOT buy. One config.issuer feeds both the
    signer and this verifier, so it cannot catch an issuer disagreement; the
    disagreement that matters is control.toml versus warden.toml, in another
    process, and the control plane is structurally unable to see it. What it
    catches is a mint() that produced a token this deployment's own verifier
    would reject.
    """
    app = FastAPI(title="warden control plane")
    verifier = Verifier(signer.public_key_pem(), issuer=issuer)

    @app.post("/v1/tokens")
    def mint_token(request: TokenRequest) -> dict:
        # ONE clock read, passed to both. mint() and verify() each read
        # time.time() otherwise, and a second ticking over between them
        # expires the token that was just signed: measured with
        # ttl_seconds=0, 4 failures in 200,000 mints. The loader now refuses
        # a non-positive TTL, which removes that configuration -- this
        # removes the race itself, and is the same discipline spine.py
        # already states for the serving path ("One clock read for the whole
        # call").
        now = int(time.time())
        raw = signer.mint(**request.model_dump(), now=now)
        token = verifier.verify(raw, now=now)

        try:
            record_mint(audit, token=token, request_digest=args_digest(request.model_dump()))
        except OSError:
            # Fails CLOSED, and this is the bigger of the two claims B7
            # makes. The repo's best-effort sites (proxy.py's refusal path,
            # spine.py's handshake refusal) both justify themselves on two
            # conditions: the outcome is a REFUSAL, and there is no channel
            # to report an unavailable log through. A mint satisfies
            # neither -- its answer can be "yes", and this is an ordinary
            # JSON route with a body.
            #
            # For a persistently unwritable log the cost is nil: the broker
            # shares this file, so the spine is already refusing every tool
            # call and the proxy every tunnel, and a token minted anyway
            # could invoke nothing and tunnel nothing. For _acquire's
            # contention timeout the cost is real -- the log is writable and
            # someone else is writing it -- and closed is still the choice,
            # because an unrecorded grant is the one thing B7 exists to
            # remove.
            raise HTTPException(status_code=503, detail=MINT_UNAVAILABLE_MESSAGE) from None

        # Returned only after the grant is durable. The token existed in
        # memory first -- jti and exp do not exist until it does -- but
        # nothing has HAPPENED until this response goes out, so the record
        # still precedes the act. Same shape as the spine's _append-then-
        # execute, and the same residual: a record written for a response
        # that never arrived. That errs toward over-recording, which is the
        # safe direction.
        return {"token": raw}

    return app
