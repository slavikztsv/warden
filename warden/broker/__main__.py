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

from warden.broker.app import create_app
from warden.broker.audit import AuditLog
from warden.broker.config.catalog import load_catalog
from warden.broker.config.loader import BrokerConfig, ConfigError, load_broker_config
from warden.broker.identity import Verifier
from warden.broker.pdp import PolicyDecisionPoint
from warden.broker.policy_digest import policy_bundle_digest
from warden.broker.proxy import serve_proxy
from warden.broker.taint import TaintTracker
from warden.broker.wiring import BrokerComponents


def _silence_telemetry() -> None:
    """The MCP SDK installs an OpenTelemetry middleware as its outermost
    layer. In an image that also carries the OTel SDK with the standard
    environment variables set, the enforcement point would begin exporting
    spans -- tool names and request ids -- to a collector. That is network
    egress from the one process whose whole premise is being the only route
    out, and it appears in no audit record.

    Installs a no-op provider, then VERIFIES the install took, and refuses
    to start if it did not. opentelemetry.trace.set_tracer_provider() is
    backed by a process-global set-once: the first caller in the PROCESS
    wins, not the first caller in this codebase. An external
    auto-instrumentation wrapper -- opentelemetry-instrument, a Kubernetes
    OTel Operator webhook, a site-wide sitecustomize.py -- can install a real
    provider before this module is even imported, in which case
    set_tracer_provider() here raises nothing and silently no-ops (it only
    logs a warning, easy to miss in production), leaving the broker to boot
    believing telemetry is silenced while a live exporter stays installed.
    Checking the outcome, not just making the call, is what closes that gap.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.trace import NoOpTracerProvider
    except ImportError:
        return
    trace.set_tracer_provider(NoOpTracerProvider())
    if type(trace.get_tracer_provider()) is not NoOpTracerProvider:
        raise ConfigError(
            "a TracerProvider was already installed before the broker started, "
            "so telemetry cannot be guaranteed silent. Do not run this process "
            "under an OpenTelemetry auto-instrumentation wrapper "
            "(opentelemetry-instrument, a Kubernetes OTel Operator webhook, or a "
            "site-wide sitecustomize.py)."
        )


def build(config: BrokerConfig, *, client: httpx.Client | None = None):
    """Wires the enforcement point from a parsed config.

    Returned as (app, components) so the proxy shares exactly the same
    verifier, PDP, taint tracker and audit log as the tool API -- two
    surfaces, one set of controls.
    """
    _silence_telemetry()
    client = client or httpx.Client(timeout=10.0)
    components = BrokerComponents(
        # Public key only. There is no Signer in this process. issuer is
        # configured (not the ISSUER constant) so a warden.toml/control.toml
        # mismatch fails every verification loudly, rather than the two
        # processes silently agreeing on a hardcoded default forever.
        verifier=Verifier.from_public_key_file(config.public_key, issuer=config.issuer),
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
        # -- a deployment-supplied tools.toml, mounted from outside the
        # product tree), the same three values compose.yml sets on the
        # broker service's `environment:`.
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
