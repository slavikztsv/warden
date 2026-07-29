"""Control plane: the only place tokens are minted.

Served on a separate port bound to the control-plane interface. The agent is
not attached to that network, so it cannot reach this route at all -- the
escalation path is closed by binding rather than by an auth check.
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
