"""The policy gate.

Every input in tests/golden/decisions/ is evaluated by the REAL opa binary
against the REAL policy bundle -- warden/policies/authz.rego plus
demo/scenario/data.json, the same two files compose.yml flat-mounts into the
opa container -- with NO `with` overrides. That last part is the whole
point: authz_test.rego mocks data.purposes and data.limits
in almost every case, so the shipped data document's shape is barely
exercised -- the file's own R1c comment says as much -- and Phase 2 adding a
correct data.tools mock everywhere would reintroduce that blindness on a new
key. Verified during design: that mock edit yields opa test PASS 44/44 over a
policy that approves a mislabelled 5,000,000-row read at runtime.

This is also the gate warden replay cannot be: replay reads a recorded log
and never calls the PDP.

Queries `data.warden.authz` -- both `allow` and `deny_reasons` -- rather than
`deny_reasons` alone. `broker/pdp.py` reads `allow` directly (pdp.py:48); a
corpus that only ever inspects `deny_reasons` cannot see a policy that stops
computing `allow` correctly from it. Verified: `default allow := true` in
place of `allow if count(deny_reasons) == 0` left the previous, deny_reasons-
only version of this suite at 15/15 PASS while `demo-4-bulk-read` -- a
10,312-row read whose frozen rule is rows.bounded -- evaluated allow: true.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools.capture_expected import EXPECTED_CASE_COUNT
from tools.opa_version import resolve_opa
from warden.broker.pdp import DENY_PRECEDENCE

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CORPUS = REPO_ROOT / "tests" / "golden" / "decisions"


def _cases() -> list[str]:
    return sorted(p.stem for p in CORPUS.glob("*.json") if p.stem != "expected")


def _evaluate(binary: str, document: dict) -> dict:
    result = subprocess.run(
        # Two -d roots since Task 22 split the bundle: the rules directory
        # (warden/policies/, which also holds authz_test.rego -- opa eval
        # loads it too, but it declares no data.* values so it is inert
        # here) and the deployment's data.json, named directly rather than
        # via its containing demo/scenario/ directory so tools.toml,
        # warden.toml etc. are not pulled into the bundle opa evaluates.
        [binary, "eval", "-I", "-d", str(REPO_ROOT / "warden" / "policies"),
         "-d", str(REPO_ROOT / "demo" / "scenario" / "data.json"),
         "data.warden.authz", "--format=json"],
        input=json.dumps(document), capture_output=True, text=True,
        cwd=REPO_ROOT, check=False,
    )
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
    return {"allow": value["allow"], "deny_reasons": sorted(value["deny_reasons"])}


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
    outcome = _evaluate(opa_binary, document)
    assert outcome["deny_reasons"] == expected["deny_reasons"], case
    assert outcome["allow"] == expected["allow"], case
    # The policy's own invariant (authz.rego:17): `allow if count(deny_reasons)
    # == 0`. Asserting it here, against the live evaluation and not just
    # against the frozen expectation, is what makes a `default allow := true`
    # mutation impossible to sneak past even if expected.json were somehow
    # captured from the same broken bundle.
    assert outcome["allow"] == (outcome["deny_reasons"] == []), case
    assert _rule(outcome["deny_reasons"]) == expected["rule"], case


def test_every_case_has_an_expectation():
    expected = json.loads((CORPUS / "expected.json").read_text())
    assert sorted(expected) == _cases()


def test_corpus_has_the_expected_case_count():
    """parametrize over an empty (or partial) glob does not fail loudly: with
    zero cases it collapses to a single [NOTSET] SKIP, exit 0 -- the same
    outward shape as "corpus not built yet". The realistic way this happens
    is not deletion but a directory move (Phase 3 of this plan moves
    directories) followed by a routine re-capture, which would otherwise
    write a smaller, perfectly self-consistent expected.json and every other
    check in this file would stay green. Asserting the count against a named
    constant -- shared with tools/capture_expected.py, which refuses to
    capture when it disagrees -- turns that into a loud failure instead."""
    assert len(_cases()) == EXPECTED_CASE_COUNT


def test_no_reason_is_unrankable():
    """A deny_reasons member DENY_PRECEDENCE cannot rank makes pdp.py fall
    through to pdp.unavailable -- the replay then names a control that never
    fired. The rekeying must introduce zero new reason strings."""
    expected = json.loads((CORPUS / "expected.json").read_text())
    for case, outcome in expected.items():
        assert outcome["rule"] != "UNRANKED", case
        for reason in outcome["deny_reasons"]:
            assert reason in DENY_PRECEDENCE, f"{case}: {reason}"
