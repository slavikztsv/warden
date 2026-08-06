"""Reads the broker's wiring from TOML.

tomllib is stdlib from 3.11, so this costs the enforcement point no
dependency -- which is the same reason a model SDK is not among the four
packages warden/pyproject.toml declares.

Every failure raises ConfigError, and the entrypoint lets it kill the
process. A broker that starts with a half-understood config writes audit
records claiming a policy it is not enforcing, and that is worse than not
starting.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    """Any reason this config cannot be used. Always names the offending key."""


@dataclass(frozen=True)
class McpConfig:
    """The MCP surface's wiring. Off unless a deployment says otherwise.

    `host` becomes the SDK's transport-security allow-list. Left unset,
    broker/mcp.py passes no settings at all, which is what lets the SDK apply
    its own rule: `streamable_http_app` turns DNS-rebinding protection ON,
    with a loopback allow-list, whenever it was given a loopback host -- and
    its `host` argument defaults to 127.0.0.1. The surface then answers 421
    "Invalid Host header" to every request arriving under a real hostname.
    Verified, not assumed: tests/warden/test_mcp_surface.py asserts both
    halves against the installed SDK.

    Note what that loopback list accepts -- `127.0.0.1:*`, `localhost:*`,
    `[::1]:*` -- patterns that require a port, so even a bare
    `Host: 127.0.0.1` on port 80 is refused. Loopback with no port is not a
    configuration this surface can serve; name the host.
    """

    enabled: bool = False
    path: str = "/mcp"
    host: str = ""


@dataclass(frozen=True)
class TaskStateConfig:
    """Two independent clocks, and conflating them is the mistake this type
    exists to prevent.

    `max_in_flight_seconds` bounds ONE call. It is the deadline on a
    reservation, and it exists to collect a charge whose broker died before it
    could settle. It MUST exceed the slowest `execute()`, or a live call's
    reservation is collected while it is still running and its budget is
    handed to a concurrent caller. The default is six times the shared
    `httpx.Client(timeout=10.0)` in broker/__main__.py that bounds every
    HTTP-shaped adapter.

    `ttl_grace_seconds` bounds a whole TASK, and exists only because task
    state deliberately survives token renewal -- so eviction can key off
    nothing but the last token's expiry, plus a grace. A task silent for
    longer than that loses its budget and its held classes, and an
    orchestrator re-minting the same task_id afterwards gets a clean task.
    Raise it to keep state longer and pay in memory; C3 (revocation) is the
    control for ending a task NOW, not this.
    """

    max_in_flight_seconds: int = 60
    ttl_grace_seconds: int = 3600
    # "memory" (the default) or "redis". Memory stays the default so every
    # config written before this existed keeps loading, and so the demo runs
    # with no Redis at all.
    backend: str = "memory"
    # Required when backend = "redis", and interpolated, so a password stays
    # out of the mounted TOML and an unset ${REDIS_URL} fails at boot rather
    # than at the first request.
    url: str = ""
    # Bounded on purpose. redis-py defaults this to None -- no timeout -- so a
    # hung Redis would block the calling thread forever, and since A6 those
    # threads are a pool of 16 shared with the egress proxy. An
    # unreachable-but-not-refusing server would exhaust the broker rather than
    # fail it. Must stay below max_in_flight_seconds: a store call that could
    # outlive the reservation it is taking is a contradiction.
    socket_timeout_seconds: int = 2


@dataclass(frozen=True)
class BrokerConfig:
    listen: tuple[str, int]
    proxy_listen: tuple[str, int]
    public_key: Path
    opa_url: str
    decision_path: str
    bundle_roots: tuple[Path, ...]
    audit_path: Path
    # issuer, not ttl_seconds: the broker VERIFIES a token's issuer (so it
    # must agree with control.toml's, or every token is rejected) but never
    # MINTS one, so a TTL here would be parsed and never consumed -- exactly
    # the silent-no-op failure this loader exists to prevent. ttl_seconds
    # lives in ControlConfig only.
    issuer: str
    catalog_path: Path
    # How many threads serve requests. This IS the broker's concurrency
    # limit, and it is configuration rather than a machine fact on purpose:
    # asyncio's default executor is min(32, cpu_count + 4), which is
    # invisible, machine-dependent, and shared with anything else in the
    # process that reaches for it. A product whose pitch is stating its own
    # limits does not get to have an undocumented one.
    #
    # ONE pool serves the tool API and the egress proxy, which already share
    # one event loop. A burst of slow tool calls therefore delays CONNECT
    # authorization -- strictly better than before, when one slow read
    # blocked every CONNECT completely, and it fails in the safe direction:
    # a queued CONNECT waits, it is never wrongly allowed.
    worker_threads: int = 16
    mcp: McpConfig = McpConfig()
    task_state: TaskStateConfig = TaskStateConfig()


def interpolate(value: str, env: Mapping[str, str]) -> str:
    """Expands ${VAR}. An unset variable RAISES rather than substituting "".

    Substituting empty would point the PDP at nothing, or the audit log at
    the current directory -- failures discovered in production rather than at
    boot.
    """
    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in env:
            raise ConfigError(f"${{{name}}} is not set in the environment")
        return env[name]

    return _VAR.sub(replace, value)


def _section(document: dict, name: str) -> dict:
    value = document.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"missing or malformed section [{name}]")
    return value


def _optional_section(document: dict, name: str) -> dict:
    """A section that may legitimately be absent.

    _section() raises on a missing table, which is right for the six the
    broker cannot run without. A surface that is off by default is the
    opposite case: every config written before it existed has no such table,
    and all of them must keep loading.
    """
    value = document.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"malformed section [{name}]")
    return value


def _flag(section: dict, table: str, key: str) -> bool:
    """A strict boolean. Duplicated from config/schema.py rather than
    imported: schema.py imports ConfigError from here, so the other
    direction is a cycle. Four lines is cheaper than restructuring both."""
    value = section.get(key, False)
    if not isinstance(value, bool):
        raise ConfigError(f"{table}.{key} must be true or false")
    return value


def _string(section: dict, table: str, key: str, env: Mapping[str, str]) -> str:
    value = section.get(key)
    if not isinstance(value, str):
        raise ConfigError(f"{table}.{key} must be a string")
    result = interpolate(value, env)
    if not result:
        raise ConfigError(f"{table}.{key} must not be empty")
    return result


def _integer(section: dict, table: str, key: str) -> int:
    value = section.get(key)
    # bool is an int subclass; a `true` here is a mistake, not a 1.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{table}.{key} must be an integer")
    return value


def _positive(
    section: dict, table: str, key: str, default: int, *, allow_zero: bool = False
) -> int:
    """An optional integer duration, defaulted, and refused if it is not a
    duration a broker can serve with.

    A zero or negative `max_in_flight_seconds` means every reservation is
    already expired the instant it is taken, so a charge is collected by the
    same call that made it and the row budget silently holds nothing --
    exactly the class of quiet weakening this loader exists to turn into a
    boot failure. Zero IS meaningful for the grace, though: it means task
    state dies with the token that last touched it.
    """
    if key not in section:
        return default
    value = _integer(section, table, key)
    if value < 0 or (value == 0 and not allow_zero):
        raise ConfigError(
            f"{table}.{key} must be "
            f"{'zero or greater' if allow_zero else 'greater than zero'}, got {value}"
        )
    return value


def _address(section: dict, table: str, key: str, env: Mapping[str, str]) -> tuple[str, int]:
    raw = _string(section, table, key, env)
    host, separator, port = raw.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise ConfigError(f"{table}.{key} must be host:port, got {raw!r}")

    # Reject unbracketed IPv6 addresses: if host contains : and is not bracketed, it's bare IPv6
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        raise ConfigError(f"{table}.{key}: host contains ':'; bracket an IPv6 literal as [::1]:8080")

    # Handle IPv6 literals: [::1]:8080 -> host=::1, port=8080
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    # Validate port range: must be 1-65535
    port_num = int(port)
    if port_num < 1 or port_num > 65535:
        raise ConfigError(f"{table}.{key}: port must be 1-65535, got {port_num}")

    return host, port_num


def _paths(section: dict, table: str, key: str, env: Mapping[str, str]) -> tuple[Path, ...]:
    value = section.get(key)
    if not isinstance(value, Sequence) or isinstance(value, str) or not value:
        raise ConfigError(f"{table}.{key} must be a non-empty array of paths")
    roots = []
    for entry in value:
        if not isinstance(entry, str):
            raise ConfigError(f"{table}.{key} entries must be strings")
        interpolated = interpolate(entry, env)
        if not interpolated:
            raise ConfigError(f"{table}.{key} entries must not be empty")
        roots.append(Path(interpolated))
    return tuple(roots)


def _load_toml(path: Path) -> dict:
    """Shared by load_broker_config and load_control_config: same
    TOML-or-die failure mode, same error messages, for both configs."""
    path = Path(path)
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc


def load_broker_config(path: Path, env: Mapping[str, str]) -> BrokerConfig:
    document = _load_toml(path)

    broker = _section(document, "broker")
    identity = _section(document, "identity")
    policy = _section(document, "policy")
    audit = _section(document, "audit")
    tokens = _section(document, "tokens")
    catalog = _section(document, "catalog")
    mcp = _optional_section(document, "mcp")
    task_state = _optional_section(document, "task_state")

    return BrokerConfig(
        listen=_address(broker, "broker", "listen", env),
        proxy_listen=_address(broker, "broker", "proxy_listen", env),
        public_key=Path(_string(identity, "identity", "public_key", env)),
        opa_url=_string(policy, "policy", "opa_url", env),
        decision_path=_string(policy, "policy", "decision_path", env),
        bundle_roots=_paths(policy, "policy", "bundle_roots", env),
        audit_path=Path(_string(audit, "audit", "path", env)),
        issuer=_string(tokens, "tokens", "issuer", env),
        catalog_path=Path(_string(catalog, "catalog", "tools", env)),
        worker_threads=_positive(broker, "broker", "worker_threads", 16),
        mcp=McpConfig(
            enabled=_flag(mcp, "mcp", "enabled"),
            path=_string(mcp, "mcp", "path", env) if "path" in mcp else "/mcp",
            host=_string(mcp, "mcp", "host", env) if "host" in mcp else "",
        ),
        task_state=_task_state_config(task_state, env),
    )


def _task_state_config(section: dict, env: Mapping[str, str]) -> TaskStateConfig:
    backend = section.get("backend", "memory")
    if backend not in ("memory", "redis"):
        raise ConfigError(
            f'task_state.backend must be "memory" or "redis", got {backend!r}'
        )
    if backend == "redis" and "url" not in section:
        # Named rather than defaulted. A localhost default would let a
        # deployment that meant to share a store silently keep its own,
        # which is the exact failure this backend exists to remove.
        raise ConfigError('task_state.url is required when backend = "redis"')
    url = _string(section, "task_state", "url", env) if "url" in section else ""

    max_in_flight = _positive(section, "task_state", "max_in_flight_seconds", 60)
    socket_timeout = _positive(section, "task_state", "socket_timeout_seconds", 2)
    if socket_timeout >= max_in_flight:
        raise ConfigError(
            "task_state.socket_timeout_seconds must be less than "
            f"max_in_flight_seconds ({socket_timeout} >= {max_in_flight}); a store "
            "call that can outlive the reservation it takes would let the "
            "deadline collect a live call's budget"
        )
    return TaskStateConfig(
        max_in_flight_seconds=max_in_flight,
        ttl_grace_seconds=_positive(
            section, "task_state", "ttl_grace_seconds", 3600, allow_zero=True
        ),
        backend=backend,
        url=url,
        socket_timeout_seconds=socket_timeout,
    )


@dataclass(frozen=True)
class ControlConfig:
    listen: tuple[str, int]
    private_key: Path
    # issuer must agree with BrokerConfig.issuer, or every minted token
    # fails verification. ttl_seconds governs minting only, so it lives
    # here and nowhere else -- the broker never mints.
    issuer: str
    ttl_seconds: int


def load_control_config(path: Path, env: Mapping[str, str]) -> ControlConfig:
    """Reads the control plane's wiring the same way load_broker_config does:
    same TOML-or-die failure mode, same ${VAR} interpolation. The control
    plane's config is smaller -- one listen address, one key path, one
    [tokens] table -- but a config it cannot fully understand must still
    refuse to start rather than mint tokens under a guess.
    """
    document = _load_toml(path)

    control = _section(document, "control")
    identity = _section(document, "identity")
    tokens = _section(document, "tokens")

    return ControlConfig(
        listen=_address(control, "control", "listen", env),
        private_key=Path(_string(identity, "identity", "private_key", env)),
        issuer=_string(tokens, "tokens", "issuer", env),
        ttl_seconds=_integer(tokens, "tokens", "ttl_seconds"),
    )
