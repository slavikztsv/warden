"""The CLIs are real commands, and the dependency direction is one-way."""

from __future__ import annotations

import subprocess
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


def test_both_commands_run():
    for command in ("warden", "warden-demo"):
        result = subprocess.run([command, "--help"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
