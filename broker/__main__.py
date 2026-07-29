"""Runs all three broker surfaces: agent-facing, control-plane, and proxy."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import httpx
import uvicorn

from broker.app import create_app
from broker.audit import AuditLog
from broker.backends import Backends
from broker.control import create_control_app
from broker.identity import Signer, Verifier
from broker.pdp import PolicyDecisionPoint
from broker.policy_digest import policy_bundle_digest
from broker.proxy import serve_proxy
from broker.taint import TaintTracker


async def main() -> None:
    signer = Signer.generate()
    Path("/run/warden").mkdir(parents=True, exist_ok=True)
    Path("/run/warden/agent.pub").write_bytes(signer.public_key_pem())

    client = httpx.Client(timeout=10.0)
    deps = {
        "verifier": Verifier(signer.public_key_pem()),
        "pdp": PolicyDecisionPoint(os.environ["OPA_URL"], client=client),
        "taint": TaintTracker(),
        "audit": AuditLog(Path(os.environ["AUDIT_PATH"])),
        "policy_digest": policy_bundle_digest(Path("/policies")),
    }
    app = create_app(
        backends=Backends(
            docstore_url=os.environ["DOCSTORE_URL"],
            db_path=Path(os.environ["DB_PATH"]),
            mailer_url=os.environ["MAILER_URL"],
            client=client,
        ),
        **deps,
    )

    proxy_server = await serve_proxy("0.0.0.0", 3128, **deps)
    agent_api = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=8080, log_level="warning"))
    control_api = uvicorn.Server(
        uvicorn.Config(create_control_app(signer=signer), host="0.0.0.0", port=8081, log_level="warning")
    )
    async with proxy_server:
        await asyncio.gather(agent_api.serve(), control_api.serve())


if __name__ == "__main__":
    asyncio.run(main())
