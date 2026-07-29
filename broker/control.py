"""Control plane: the only place tokens are minted.

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
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from broker.identity import Signer


class TokenRequest(BaseModel):
    agent_id: str
    task_id: str
    purpose: str
    allowed_tools: list[str]
    data_classes: list[str]
    counterparties: list[str]


def create_control_app(*, signer: Signer) -> FastAPI:
    app = FastAPI(title="warden control plane")

    @app.post("/v1/tokens")
    def mint_token(request: TokenRequest) -> dict:
        return {
            "token": signer.mint(
                agent_id=request.agent_id,
                task_id=request.task_id,
                purpose=request.purpose,
                allowed_tools=request.allowed_tools,
                data_classes=request.data_classes,
                counterparties=request.counterparties,
            )
        }

    return app
