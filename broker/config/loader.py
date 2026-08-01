"""Reads the broker's wiring from TOML.

tomllib is stdlib from 3.11, so this costs the enforcement point no
dependency -- which is the same reason a model SDK is not in
requirements.txt.

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
class BrokerConfig:
    listen: tuple[str, int]
    proxy_listen: tuple[str, int]
    public_key: Path
    opa_url: str
    decision_path: str
    bundle_roots: tuple[Path, ...]
    audit_path: Path
    issuer: str
    ttl_seconds: int
    catalog_path: Path


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


def _string(section: dict, table: str, key: str, env: Mapping[str, str]) -> str:
    value = section.get(key)
    if not isinstance(value, str):
        raise ConfigError(f"{table}.{key} must be a string")
    return interpolate(value, env)


def _integer(section: dict, table: str, key: str) -> int:
    value = section.get(key)
    # bool is an int subclass; a `true` here is a mistake, not a 1.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{table}.{key} must be an integer")
    return value


def _address(section: dict, table: str, key: str, env: Mapping[str, str]) -> tuple[str, int]:
    raw = _string(section, table, key, env)
    host, separator, port = raw.rpartition(":")
    if not separator or not host or not port.isdigit():
        raise ConfigError(f"{table}.{key} must be host:port, got {raw!r}")
    return host, int(port)


def _paths(section: dict, table: str, key: str, env: Mapping[str, str]) -> tuple[Path, ...]:
    value = section.get(key)
    if not isinstance(value, Sequence) or isinstance(value, str) or not value:
        raise ConfigError(f"{table}.{key} must be a non-empty array of paths")
    roots = []
    for entry in value:
        if not isinstance(entry, str):
            raise ConfigError(f"{table}.{key} entries must be strings")
        roots.append(Path(interpolate(entry, env)))
    return tuple(roots)


def load_broker_config(path: Path, env: Mapping[str, str]) -> BrokerConfig:
    path = Path(path)
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    broker = _section(document, "broker")
    identity = _section(document, "identity")
    policy = _section(document, "policy")
    audit = _section(document, "audit")
    tokens = _section(document, "tokens")
    catalog = _section(document, "catalog")

    return BrokerConfig(
        listen=_address(broker, "broker", "listen", env),
        proxy_listen=_address(broker, "broker", "proxy_listen", env),
        public_key=Path(_string(identity, "identity", "public_key", env)),
        opa_url=_string(policy, "policy", "opa_url", env),
        decision_path=_string(policy, "policy", "decision_path", env),
        bundle_roots=_paths(policy, "policy", "bundle_roots", env),
        audit_path=Path(_string(audit, "audit", "path", env)),
        issuer=_string(tokens, "tokens", "issuer", env),
        ttl_seconds=_integer(tokens, "tokens", "ttl_seconds"),
        catalog_path=Path(_string(catalog, "catalog", "tools", env)),
    )
