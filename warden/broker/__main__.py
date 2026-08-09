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
from warden.broker.taint import InMemoryTaskStateStore
from warden.broker.wiring import BrokerComponents, build_executor


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

    CALLED UNCONDITIONALLY, as the first line of `build()` -- not gated
    behind `config.mcp.enabled`, even though the one CONCRETE trigger named
    above (the MCP SDK's own middleware) cannot fire unless the MCP surface
    is actually mounted: `warden.broker.mcp` -- and therefore the `mcp`
    package -- is only ever imported inside `create_app`'s `if mcp is not
    None and mcp.enabled` branch, so a deployment with the surface off never
    loads code that could install that particular middleware. Scoping this
    call to that branch would still be SOUND for the trigger described above.
    It is not done, for a reason bigger than that one trigger: OpenTelemetry's
    TracerProvider is a property of the PROCESS, not of one surface inside
    it, and `opentelemetry-api` can be present in an image for reasons that
    have nothing to do with `warden[mcp]` -- another dependency pulling it in,
    an operator's own observability tooling, a base image that ships it. Any
    of those, combined with an external auto-instrumentation wrapper around
    the whole `warden serve` invocation, would instrument the enforcement
    point's OWN FastAPI app and its outbound httpx calls to OPA and the
    adapters -- exporting the exact same class of sensitive span (tool names,
    task ids, decisions) this function exists to stop, with no MCP surface
    involved at all. A deployment that never enables MCP is not exempt from
    that risk, so it is not exempt from this check either. The cost of
    checking regardless is one no-op provider install on every boot; the
    cost of not checking is the silent, unaudited leak this whole function
    exists to close, on exactly the deployments that assumed being MCP-free
    made them safe from it.
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


def _build_task_state(config: BrokerConfig):
    """The store named by [task_state].backend.

    The import is inside the branch, not at module scope, for the same reason
    the MCP surface's is: `redis` is an optional extra, and a deployment
    running the default in-memory backend must not need it installed to
    start. A missing extra is reported as a missing extra, at boot, rather
    than as an ImportError at the first request.
    """
    if config.task_state.backend == "memory":
        return InMemoryTaskStateStore(
            max_in_flight_seconds=config.task_state.max_in_flight_seconds
        )

    try:
        from warden.broker.taint_redis import RedisTaskStateStore, connect
    except ImportError as exc:
        if exc.name is not None and exc.name.split(".")[0] != "redis":
            # A typo'd first-party import inside taint_redis.py raises
            # ImportError too, and reporting that as "install warden[redis]"
            # would send whoever hits it to reinstall a package already there.
            raise
        raise ConfigError(
            '[task_state].backend is "redis" but the redis extra is not '
            "installed; install warden[redis]"
        ) from exc

    return RedisTaskStateStore(
        connect(
            config.task_state.url,
            socket_timeout_seconds=config.task_state.socket_timeout_seconds,
        ),
        max_in_flight_seconds=config.task_state.max_in_flight_seconds,
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
        # One store, shared by the tool API and the proxy, which is what makes
        # a task's budget one budget rather than two. Which implementation is
        # a config choice: in-process by default, Redis when a deployment
        # wants that budget shared between BROKERS as well.
        task_state=_build_task_state(config),
        audit=AuditLog(
            config.audit_path,
            durability=config.audit_durability,
            segment_bytes=config.audit_segment_bytes,
        ),
        # Computed once at startup, never lazily per request: a missing or
        # unreadable bundle must crash before the first decision, not be
        # discovered halfway through serving one.
        policy_digest=policy_bundle_digest(config.bundle_roots),
        # One pool, both surfaces -- the same reason they share one spine and
        # one store. Two pools would be two independent concurrency limits on
        # one event loop, and neither would be the number an operator set.
        executor=build_executor(config.worker_threads),
    )
    app = create_app(
        # DOCSTORE_URL, DB_PATH and MAILER_URL are read from the process
        # environment here rather than from config: they interpolate the
        # ${VAR} bindings inside the tool manifest itself (config.catalog_path
        # -- a deployment-supplied tools.toml, mounted from outside the
        # product tree), the same three values compose.yml sets on the
        # broker service's `environment:`.
        catalog=load_catalog(config.catalog_path, os.environ, client),
        # Not in components: BrokerComponents feeds serve_proxy too, which has
        # no MCP surface and would raise TypeError on the extra keyword. The
        # grace below is out for the same reason -- the proxy charges nothing,
        # so it has no reservation whose task lifetime this would set.
        mcp=config.mcp,
        state_grace_seconds=config.task_state.ttl_grace_seconds,
        # Out of BrokerComponents' kwargs for the same reason those two are,
        # and one more: as_proxy_kwargs() is splatted into authorize_connect,
        # which is keyword-only with no **kwargs. Passed explicitly to each
        # surface instead.
        executor=components.executor,
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
    proxy_server = await serve_proxy(
        proxy_host,
        proxy_port,
        executor=components.executor,
        **components.as_proxy_kwargs(),
    )
    agent_api = uvicorn.Server(
        uvicorn.Config(app, host=api_host, port=api_port, log_level="warning")
    )
    async with proxy_server:
        try:
            await agent_api.serve()
        finally:
            # wait=True: a thread part-way through execute() is holding a
            # reservation, and dropping it on the floor leaks one until its
            # deadline collects it. Draining is what makes a clean shutdown
            # clean rather than merely quick.
            components.executor.shutdown(wait=True)


if __name__ == "__main__":
    asyncio.run(main())
