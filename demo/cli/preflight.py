"""What can actually run right now, and why not when it cannot.

The menu labels options ready or blocked, so this has to agree with the code
that would do the work. Two commitments:

  · Provider selection mirrors demo/agent/llm.py's live_client_from_env --
    openrouter, then gemini, with WARDEN_PROVIDER overriding the precedence
    outright and FAILING rather than falling back when the provider it names
    has no key. A menu that promises a run which then dies on a missing
    credential is worse than no label at all.
  · demo/cli/sweep.py needs OPENROUTER_API_KEY specifically, not any live
    key, so callers ask about that separately.

The key names are duplicated here rather than imported because
live_client_from_env builds its table inside the function body, and importing
that module drags in the vendor SDKs it exists to guard -- which is precisely
what a "can I go live?" check must not require.
tests/demo/test_preflight.py pins these names against llm.py's source so the
duplication cannot drift silently.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path

LIVE_KEYS = {
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
}

# The order live_client_from_env tries them in.
PRECEDENCE = ("openrouter", "gemini")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOTENV_PATH = REPO_ROOT / ".env"


def dotenv_values(path: Path) -> dict[str, str]:
    """Parses a .env well enough for credential detection.

    Not a general dotenv implementation: no interpolation, no `export`
    prefixes, no multi-line values. It reads exactly the shape .env.example
    ships, and an unreadable or absent file yields nothing rather than
    raising -- not having a .env is the normal case, not an error.
    """
    try:
        text = Path(path).read_text()
    except OSError:
        return {}

    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key.strip()] = value
    return values


def merged_env(
    env: Mapping[str, str] | None = None, *, dotenv_path: Path | None = None
) -> dict[str, str]:
    """The environment a live run would actually see: .env underneath, the
    process environment on top. Compose resolves ${VAR} the same way round,
    so a shell export must win over a stale file."""
    base = dotenv_values(DOTENV_PATH if dotenv_path is None else dotenv_path)
    base.update(os.environ if env is None else env)
    return base


def _present(env: Mapping[str, str], key: str) -> bool:
    return bool((env.get(key) or "").strip())


def live_provider(env: Mapping[str, str]) -> str | None:
    """The provider a `--live` run would use, or None if it could not start.

    Returning None for a WARDEN_PROVIDER naming a provider with no key is
    deliberate and matches llm.py, which raises there instead of quietly
    falling back to a different vendor than the operator asked for.
    """
    forced = (env.get("WARDEN_PROVIDER") or "").strip().lower()
    if forced:
        if forced not in LIVE_KEYS or not _present(env, LIVE_KEYS[forced]):
            return None
        return forced

    for name in PRECEDENCE:
        if _present(env, LIVE_KEYS[name]):
            return name
    return None


def has_openrouter(env: Mapping[str, str]) -> bool:
    """sweep's specific requirement, separate from live_provider: a gemini
    key makes `--live` work and `sweep` still exit."""
    return _present(env, LIVE_KEYS["openrouter"])


def docker_available(which: Callable[[str], str | None] = shutil.which) -> bool:
    """Whether a `docker` binary is on PATH.

    Deliberately not `docker info`: that is a second or more of latency on a
    menu that redraws, and it still would not prove the daemon stays up until
    the command runs. This answers "is Docker plausibly here", and the
    command itself reports the real failure.
    """
    return which("docker") is not None
