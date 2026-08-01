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
from broker.config.catalog import load_catalog
from broker.config.loader import BrokerConfig, load_broker_config
from broker.identity import Verifier
from broker.pdp import PolicyDecisionPoint
from broker.policy_digest import policy_bundle_digest
from broker.proxy import serve_proxy
from broker.taint import TaintTracker
from broker.wiring import BrokerComponents


def build(config: BrokerConfig, *, client: httpx.Client | None = None):
    """Wires the enforcement point from a parsed config.

    Returned as (app, components) so the proxy shares exactly the same
    verifier, PDP, taint tracker and audit log as the tool API -- two
    surfaces, one set of controls.
    """
    client = client or httpx.Client(timeout=10.0)
    components = BrokerComponents(
        # Public key only. There is no Signer in this process.
        verifier=Verifier.from_public_key_file(config.public_key),
        pdp=PolicyDecisionPoint(
            config.opa_url, decision_path=config.decision_path, client=client
        ),
        taint=TaintTracker(),
        audit=AuditLog(config.audit_path),
        # Computed once at startup, never lazily per request: a missing or
        # unreadable bundle must crash before the first decision, not be
        # discovered halfway through serving one.
        policy_digest=policy_bundle_digest(config.bundle_roots),
    )
    app = create_app(
        # DOCSTORE_URL, DB_PATH and MAILER_URL are read from the process
        # environment here rather than from config: they interpolate the
        # ${VAR} bindings inside the tool manifest itself (config.catalog_path
        # -- e.g. demo/scenario/tools.toml), the same three values
        # docker-compose.yml sets on the broker service's `environment:`.
        catalog=load_catalog(config.catalog_path, os.environ, client),
        **components.as_app_kwargs(),
    )
    return app, components


async def main() -> None:
    config = load_broker_config(
        Path(os.environ.get("WARDEN_CONFIG", "/config/warden.toml")), os.environ
    )
    app, components = build(config)
    proxy_host, proxy_port = config.proxy_listen
    api_host, api_port = config.listen
    proxy_server = await serve_proxy(proxy_host, proxy_port, **components.as_proxy_kwargs())
    agent_api = uvicorn.Server(
        uvicorn.Config(app, host=api_host, port=api_port, log_level="warning")
    )
    async with proxy_server:
        await agent_api.serve()


if __name__ == "__main__":
    asyncio.run(main())
