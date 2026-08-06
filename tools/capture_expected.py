"""Captures tests/golden/decisions/expected.json by executing the shipped,
unmodified policies/ bundle against every case in the corpus.

expected.json records what the policy says TODAY, not what it ought to say
-- so it must never be hand-authored or hand-corrected. Before this script
existed, the capture step lived only as a shell heredoc inside a task brief
under .superpowers/ (gitignored), which meant "captured by execution, not
authored" had no committed mechanism: the next person to need a recapture
would have had no way to do it except by hand-editing the JSON, exactly the
thing this file is supposed to prevent. This is the one committed way to
produce expected.json.

Refuses to write when the corpus does not contain exactly
EXPECTED_CASE_COUNT cases. The realistic way expected.json goes silently
wrong is not "someone hand-edits it" -- it's "a directory move drops or
duplicates files (Phase 3 of this plan moves directories), and a routine
recapture afterward writes a smaller-or-larger, perfectly self-consistent
expected.json with no test able to tell the difference." Refusing here turns
that into a loud failure at capture time instead of a quietly shrunk
baseline. See tests/test_golden_decisions.py::test_corpus_has_the_expected_case_count
for the mirror-image check on the read side.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "tests" / "golden" / "decisions"

sys.path.insert(0, str(REPO_ROOT))

from tools.opa_version import bundle_args, resolve_opa  # noqa: E402
from warden.broker.pdp import DENY_PRECEDENCE  # noqa: E402

# 7 demo cases derived from the frozen audit log (tools/build_corpus.py) +
# 7 hand-authored adversarial cases. Kept as one named constant, imported by
# the test suite too, so the two checks cannot silently drift apart.
EXPECTED_CASE_COUNT = 14


def _cases() -> list[Path]:
    return sorted(p for p in CORPUS.glob("*.json") if p.stem != "expected")


def _evaluate(binary: str, document_text: str) -> dict:
    result = subprocess.run(
        # The bundle spelling comes from tools/opa_version.py, not from here.
        # This script used to build its own single-root command line, and
        # kept it when Task 22 moved data.json out of warden/policies/ --
        # which made every capture evaluate against a bundle with no
        # data.tools, no data.purposes and no data.limits, where R1b's
        # fail-closed default denies EVERYTHING as input.malformed. A run
        # would have written a perfectly self-consistent expected.json in
        # which all fourteen cases deny, and the corpus test would have
        # passed against it while asserting nothing about any rule. One
        # definition now, shared with the corpus test.
        [binary, "eval", "-I", *bundle_args(REPO_ROOT),
         "data.warden.authz", "--format=json"],
        input=document_text, capture_output=True, text=True,
        cwd=REPO_ROOT, check=True,
    )
    return json.loads(result.stdout)["result"][0]["expressions"][0]["value"]


def main() -> int:
    cases = _cases()
    if len(cases) != EXPECTED_CASE_COUNT:
        print(
            f"refusing to capture: found {len(cases)} case(s) in {CORPUS}, "
            f"expected {EXPECTED_CASE_COUNT}. The corpus is missing files, "
            f"has extras, or the constant is stale -- fix the corpus (or the "
            f"constant, deliberately), don't let a capture paper over it "
            f"with a differently-sized expected.json.",
            file=sys.stderr,
        )
        return 1

    binary = resolve_opa()
    out = {}
    for path in cases:
        value = _evaluate(binary, path.read_text())
        reasons = sorted(value["deny_reasons"])
        allow = value["allow"]
        rule = "allow" if not reasons else next(
            (c for c in DENY_PRECEDENCE if c in reasons), "UNRANKED")
        out[path.stem] = {"allow": allow, "deny_reasons": reasons, "rule": rule}
        print(f"{path.stem:<45} {rule:<18} allow={allow!s:<5} {reasons}")

    (CORPUS / "expected.json").write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
