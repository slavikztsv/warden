"""The pinned OPA version is one value, and every resolution honours it.

Three resolutions existed and only two were pinned; the unpinned pair --
cli/explain.py and the integration fixture -- ran 0.70.0 while the image and
CI ran 1.19.0. OPA 1.0 made Rego v1 the default and changed `opa test`
defaults, so a policy passing 44/44 locally was not evidence about what
ships.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tools.opa_version import OPA_VERSION, resolve_opa

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_compose_pins_the_same_version():
    compose = (REPO_ROOT / "compose.yml").read_text()
    assert f"openpolicyagent/opa:{OPA_VERSION}" in compose


def test_ci_never_restates_the_version_or_path():
    """ci.yml must not know OPA_VERSION at all.

    It runs ./scripts/fetch-opa.sh and then whatever binary that script
    resolved and published as $OPA_BIN -- it states neither a version number
    nor a binary path itself. That is the whole point of routing through
    fetch-opa.sh: a version bump touches one file, not two. The complementary
    guarantee -- that fetch-opa.sh's resolution actually tracks OPA_VERSION
    rather than hardcoding it -- is test_fetch_opa_derives_the_pinned_version
    below.
    """
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "fetch-opa.sh" in ci
    assert "OPA_BIN" in ci
    assert OPA_VERSION not in ci


def test_fetch_opa_derives_the_pinned_version():
    """fetch-opa.sh must compute its version from tools.opa_version.OPA_VERSION
    via a command substitution, not restate "1.19.0" as a literal.

    ci.yml no longer states a version anywhere (see the test above), so this
    script is the only place left that could silently drift from the pinned
    constant. This re-executes the exact substitution the script uses --
    not a reimplementation of it -- so it fails if the script stops deriving
    the version at all (no command substitution assigning VERSION) or stops
    deriving it from this module (the substitution text no longer names
    tools.opa_version / OPA_VERSION).
    """
    script = (REPO_ROOT / "scripts" / "fetch-opa.sh").read_text()
    match = re.search(r'VERSION="\$\((.+?)\)"', script)
    assert match, "fetch-opa.sh must set VERSION via a command substitution"
    substitution = match.group(1)
    assert "tools.opa_version" in substitution
    assert "OPA_VERSION" in substitution

    derived = subprocess.run(
        ["bash", "-c", substitution],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert derived == OPA_VERSION


def test_the_version_report_survives_a_reader_that_stops_early(tmp_path):
    """`"$DEST" version | head -1` under `set -o pipefail` is exit 141, sometimes.

    head exits after the first line and closes the pipe; opa, still writing its
    remaining seven lines, takes SIGPIPE. `set -o pipefail` promotes that to the
    pipeline's status and `set -e` aborts the script. So CI failed at "Install
    OPA" -- before a single test ran -- on commits that touched neither CI nor
    this script. It is a race, decided by whether the producer finished writing
    first, which is why it failed roughly one push in five rather than every
    time; locally the same construct failed 4 runs in 30.

    This runs the script's OWN reporting line with $DEST bound to a stand-in
    that writes far more than a pipe buffer, so the race always resolves the
    losing way. It therefore fails for ANY construct that stops reading early,
    not only for `head`.
    """
    script = (REPO_ROOT / "scripts" / "fetch-opa.sh").read_text()
    match = re.search(r'^"\$DEST" version.*$', script, re.MULTILINE)
    assert match, "fetch-opa.sh must report the resolved binary's version"

    producer = tmp_path / "fake-opa"
    producer.write_text(
        "#!/usr/bin/env bash\nfor i in $(seq 20000); do echo \"line $i\"; done\n"
    )
    producer.chmod(0o755)

    result = subprocess.run(
        ["bash", "-c", f'set -euo pipefail\nDEST="{producer}"\n{match.group(0)}'],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"the version report died with exit {result.returncode} "
        f"(141 = SIGPIPE) — a reader that stops early must not fail the script"
    )
    assert result.stdout.strip() == "line 1", "it must still report one line"


def test_no_module_resolves_opa_off_bare_path():
    """shutil.which("opa") anywhere means an unpinned resolution came back."""
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts or ".venv" in path.parts:
            continue
        if path.name in ("opa_version.py", "test_opa_pin.py"):
            continue
        if re.search(r'shutil\.which\(\s*["\']opa["\']\s*\)', path.read_text()):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_resolve_opa_returns_a_binary_of_the_pinned_version():
    try:
        binary = resolve_opa()
    except RuntimeError as exc:
        pytest.skip(f"pinned opa not installed: {exc}")
    assert Path(binary).is_file()


def test_a_failed_download_never_becomes_the_cached_opa_binary(tmp_path):
    """A download that fails must leave no file behind, let alone an executable one.

    `curl -sSL -o "$DEST"` exits 0 on a 404 or a CDN error page and writes the
    HTML body to $DEST; `chmod +x` then makes that "the OPA binary". The next
    line fails with a shell syntax error from trying to run HTML, which is a
    long way from "the download failed" -- and because the fast path only tests
    -x, the poisoned file is served from the version-keyed cache on every later
    run rather than being re-fetched.

    Both halves are pinned here: --fail, so curl treats an HTTP error as an
    error, and the download landing on a temp path that is only moved into
    place on success.
    """
    import os

    script = REPO_ROOT / "scripts" / "fetch-opa.sh"
    assert re.search(r"curl[^\n]*--fail", script.read_text()), \
        "curl must be given --fail, or an HTTP error page is downloaded as success"

    home = tmp_path / "home"
    home.mkdir()
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    # Stands in for curl --fail meeting a 404: it has already written part of
    # the error body to the -o target by the time it decides to exit non-zero.
    (stub_bin / "curl").write_text(
        "#!/usr/bin/env bash\n"
        "out=\n"
        'while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { out=$2; shift; }; shift; done\n'
        '[ -n "$out" ] && printf "<html>404 Not Found</html>" > "$out"\n'
        "exit 22\n"
    )
    (stub_bin / "curl").chmod(0o755)

    result = subprocess.run(
        ["bash", str(script)],
        cwd=REPO_ROOT,
        env={**os.environ, "HOME": str(home), "PATH": f"{stub_bin}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0, "a failed download must fail the step, not continue"
    cached = home / ".cache" / "warden" / f"opa-{OPA_VERSION}"
    assert not cached.exists(), f"a failed download was cached as the binary: {cached}"
    assert not list((home / ".cache" / "warden").glob("*.part.*")), \
        "the partial download must not be left behind either"
