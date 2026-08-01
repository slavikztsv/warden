"""The policy gate.

Every input in tests/golden/decisions/ is evaluated by the REAL opa binary
against the REAL policies/ directory, with NO `with` overrides. That last
part is the whole point: authz_test.rego mocks data.purposes and data.limits
in almost every case, so the shipped data document's shape is barely
exercised -- the file's own R1c comment says as much -- and Phase 2 adding a
correct data.tools mock everywhere would reintroduce that blindness on a new
key. Verified during design: that mock edit yields opa test PASS 44/44 over a
policy that approves a mislabelled 5,000,000-row read at runtime.

This is also the gate warden replay cannot be: replay reads a recorded log
and never calls the PDP.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from broker.pdp import DENY_PRECEDENCE
from tools.opa_version import resolve_opa

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "tests" / "golden" / "decisions"


def _cases() -> list[str]:
    return sorted(p.stem for p in CORPUS.glob("*.json") if p.stem != "expected")


def _evaluate(binary: str, document: dict) -> list[str]:
    result = subprocess.run(
        [binary, "eval", "-I", "-d", str(REPO_ROOT / "policies"),
         "data.warden.authz.deny_reasons", "--format=json"],
        input=json.dumps(document), capture_output=True, text=True,
        cwd=REPO_ROOT, check=False,
    )
    assert result.returncode == 0, result.stderr
    return sorted(json.loads(result.stdout)["result"][0]["expressions"][0]["value"])


def _rule(reasons: list[str]) -> str:
    if not reasons:
        return "allow"
    for candidate in DENY_PRECEDENCE:
        if candidate in reasons:
            return candidate
    # pdp.py returns pdp.unavailable here, naming a control that never fired.
    return "UNRANKED"


@pytest.fixture(scope="module")
def opa_binary() -> str:
    return resolve_opa()


@pytest.mark.parametrize("case", _cases())
def test_decision_matches_the_frozen_expectation(case, opa_binary):
    expected = json.loads((CORPUS / "expected.json").read_text())[case]
    document = json.loads((CORPUS / f"{case}.json").read_text())
    reasons = _evaluate(opa_binary, document)
    assert reasons == expected["deny_reasons"], case
    assert _rule(reasons) == expected["rule"], case


def test_every_case_has_an_expectation():
    expected = json.loads((CORPUS / "expected.json").read_text())
    assert sorted(expected) == _cases()


def test_no_reason_is_unrankable():
    """A deny_reasons member DENY_PRECEDENCE cannot rank makes pdp.py fall
    through to pdp.unavailable -- the replay then names a control that never
    fired. The rekeying must introduce zero new reason strings."""
    expected = json.loads((CORPUS / "expected.json").read_text())
    for case, outcome in expected.items():
        assert outcome["rule"] != "UNRANKED", case
        for reason in outcome["deny_reasons"]:
            assert reason in DENY_PRECEDENCE, f"{case}: {reason}"
