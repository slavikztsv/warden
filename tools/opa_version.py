"""The single pinned OPA version, the only way to find that binary, and the
only spelling of the bundle it evaluates.

Four places resolved OPA and two of them took whatever was on PATH -- 0.70.0
on the development machine, against a 1.19.0 pin in the image and in CI. OPA
1.0 made Rego v1 the default, so `opa test policies/` passing locally was not
evidence about the engine that ships. Everything routes through here now, and
a version mismatch RAISES: the alternative is a skip, and the one test that
evaluates the real policy against the real bundle must not be able to quietly
not run.

`bundle_args` is here for the identical reason, found the identical way. Task
22 moved data.json out of warden/policies/ into demo/scenario/, and of the two
callers that build an `opa eval` command line only one was updated:
tests/warden/test_golden_decisions.py gained the second -d root,
tools/capture_expected.py kept its single one. A bundle missing data.json has
no data.tools, no data.purposes and no data.limits, so R1b's fail-closed
default denies EVERY case as input.malformed -- and capture_expected.py is the
one committed way to regenerate the corpus baseline. Running it wrote an
expected.json in which all fourteen cases deny: perfectly self-consistent, and
seventeen of the corpus suite's eighteen tests still passed against it,
because a frozen expectation captured from a broken bundle agrees with a live
evaluation against that same broken bundle. Nothing caught it because that
script has no test and CI never runs it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

OPA_VERSION = "1.19.0"

# Where scripts/fetch-opa.sh puts it. Checked before PATH so a stale system
# opa cannot win.
PINNED_PATH = Path.home() / ".cache" / "warden" / f"opa-{OPA_VERSION}"


def bundle_args(repo_root: Path) -> list[str]:
    """The `-d` roots that make up the shipped policy bundle, as argv.

    Two roots, not one. The rules directory (which also holds authz_test.rego
    -- opa loads it too, but it declares no data.* values so it is inert), and
    the deployment's data.json named DIRECTLY rather than via its containing
    demo/scenario/ directory, so tools.toml, warden.toml and the rest are not
    pulled into the bundle being evaluated.
    """
    return [
        "-d", str(repo_root / "warden" / "policies"),
        "-d", str(repo_root / "demo" / "scenario" / "data.json"),
    ]


def installed_version(binary: str) -> str | None:
    """The `Version:` line from `opa version`, or None if it cannot be read."""
    try:
        result = subprocess.run(
            [binary, "version"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def resolve_opa() -> str:
    """Absolute path to an OPA binary of exactly OPA_VERSION.

    Raises rather than returning a different version. A caller that wants to
    degrade gracefully catches RuntimeError and says so out loud.
    """
    candidates = [str(PINNED_PATH)]
    from_path = shutil.which("opa")
    if from_path:
        candidates.append(from_path)
    local = Path.home() / ".local" / "bin" / "opa"
    if local.is_file():
        candidates.append(str(local))

    seen: list[str] = []
    for candidate in candidates:
        if not (Path(candidate).is_file() and os.access(candidate, os.X_OK)):
            continue
        version = installed_version(candidate)
        if version == OPA_VERSION:
            return candidate
        seen.append(f"{candidate} is {version or 'unreadable'}")

    detail = "; ".join(seen) if seen else "no opa binary found"
    raise RuntimeError(
        f"OPA {OPA_VERSION} required ({detail}). Run scripts/fetch-opa.sh."
    )
