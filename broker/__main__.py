"""The enforcement point: the agent-facing tool API and the egress proxy.

This process deliberately does NOT serve the control plane and deliberately
does NOT hold a signing key. It loads the public half of the keypair and
constructs a Verifier, nothing more.

That is a stronger statement than "the minting route is bound to another
interface". The broker is the one service the agent can reach by design, so it
is the one service most exposed to a subverted agent; a compromise of it now
yields no ability to mint a token, because the material required to sign one
was never in this address space. Minting lives in broker/control_main.py, run
as a separate service on a network the agent is not attached to.

The previous arrangement was not merely weaker, it was broken: this module
called Signer.generate() and served create_control_app() on 0.0.0.0:8081 from
the same container that is attached to agent-net, and that control app has no
authentication and lets its caller choose task_id, purpose, allowed_tools and
counterparties. The agent could therefore mint itself an arbitrary token --
and, by picking a fresh task_id, reset the taint state and the row budget too.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import httpx
import uvicorn

from broker.app import create_app
from broker.audit import AuditLog
from broker.backends import Backends
from broker.identity import Verifier
from broker.pdp import PolicyDecisionPoint
from broker.policy_digest import policy_bundle_digest
from broker.proxy import serve_proxy
from broker.taint import TaintTracker

PUBLIC_KEY_PATH = "/data/agent.pub"


def build(env: dict[str, str] | None = None, *, client: httpx.Client | None = None):
    """Wires the enforcement point from the environment.

    Returned as (app, deps) so the proxy can share exactly the same verifier,
    PDP, taint tracker and audit log as the tool API -- two surfaces, one set
    of controls -- and so a test can inspect the wiring without binding ports.
    """
    env = os.environ if env is None else env
    client = client or httpx.Client(timeout=10.0)

    deps = {
        # Public key only. There is no Signer in this process.
        "verifier": Verifier.from_public_key_file(
            env.get("AGENT_PUBLIC_KEY_PATH", PUBLIC_KEY_PATH)
        ),
        "pdp": PolicyDecisionPoint(env["OPA_URL"], client=client),
        "taint": TaintTracker(),
        "audit": AuditLog(Path(env["AUDIT_PATH"])),
        # Computed once at startup, never lazily per request: a missing or
        # unreadable policy bundle must crash before the first decision, not
        # be discovered halfway through serving one.
        "policy_digest": policy_bundle_digest(
            [Path(part) for part in env.get("POLICY_PATH", "/policies").split(":")]
        ),
    }
    app = create_app(
        backends=Backends(
            docstore_url=env["DOCSTORE_URL"],
            db_path=Path(env["DB_PATH"]),
            mailer_url=env["MAILER_URL"],
            client=client,
        ),
        **deps,
    )
    return app, deps


async def main() -> None:
    app, deps = build()

    proxy_server = await serve_proxy("0.0.0.0", 3128, **deps)
    agent_api = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=8080, log_level="warning"))
    async with proxy_server:
        await agent_api.serve()


if __name__ == "__main__":
    asyncio.run(main())
