"""The CLIs are real commands, and the dependency direction is one-way."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def project(name: str) -> dict:
    return tomllib.loads((REPO_ROOT / name / "pyproject.toml").read_text())["project"]


def test_the_product_declares_one_script():
    assert project("warden")["scripts"] == {"warden": "warden.cli.main:main"}


def test_the_demo_declares_one_script_and_depends_on_the_product():
    demo = project("demo")
    assert demo["scripts"] == {"warden-demo": "demo.cli.main:main"}
    assert any(d.split()[0].split("=")[0] == "warden" for d in demo["dependencies"])


def test_the_product_does_not_depend_on_the_demo():
    """pip enforces the seam the tests confirm."""
    for dependency in project("warden")["dependencies"]:
        assert "warden-demo" not in dependency


def test_the_product_carries_no_model_sdk():
    joined = " ".join(project("warden")["dependencies"])
    for sdk in ("anthropic", "google-genai", "openai"):
        assert sdk not in joined


def test_the_mcp_sdk_is_an_extra_not_a_dependency():
    """The enforcement point is the one service a subverted agent can reach
    on two ports. A second HTTP stack and a telemetry library belong to the
    surface that needs them, not to every deployment."""
    warden = project("warden")
    joined = " ".join(warden["dependencies"])
    assert "mcp" not in joined
    assert any(d.startswith("mcp==") for d in warden["optional-dependencies"]["mcp"])


def test_both_commands_run():
    """Resolved next to the running interpreter, not off PATH.

    subprocess.run(["warden", ...]) used to rely on PATH containing the venv's
    bin/ directory -- true only when the venv is activated. Run this suite as
    `.venv/bin/python -m pytest` from a plain shell (PATH unset to the venv)
    and the bare command name raised FileNotFoundError, so the test's own
    passing depended on how it was invoked rather than on the CLIs actually
    working. sys.executable is the interpreter pytest is running under, and
    console scripts install into the same bin/ directory as that interpreter
    -- true for a venv and for a system install alike -- so resolving there
    finds the right command regardless of PATH.
    """
    bin_dir = Path(sys.executable).parent
    for command in ("warden", "warden-demo"):
        result = subprocess.run(
            [str(bin_dir / command), "--help"], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
