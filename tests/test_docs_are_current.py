"""Docs that name a path or a command must name one that exists."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = [REPO_ROOT / "README.md", REPO_ROOT / "THREAT_MODEL.md",
        *(REPO_ROOT / "docs").glob("*.md")]

# docs/live-run-2026-07-30.md and docs/live-enforcement-2026-07-30.md are
# dated write-ups of runs that actually happened: every command line in them
# is what was run AT THAT DATE, against that day's tree layout. Rewriting
# those commands to today's invocations would misrepresent the historical
# record -- the same reason the hash-chained files under runs/ are never
# edited after the fact once written. Each of the two carries its own note
# near the top giving today's equivalents, so a reader lands on the current
# command without the historical transcript being falsified. The
# stale-invocation scan below is therefore scoped to skip only these two
# documents, by name -- not loosened for everyone, and both stay fully
# in scope for the link-existence check right after it, since a link is a
# promise about a file that exists today regardless of when the prose
# around it was written.
DATED_WRITE_UPS = {"live-run-2026-07-30.md", "live-enforcement-2026-07-30.md"}
CURRENT_DOCS = [doc for doc in DOCS if doc.name not in DATED_WRITE_UPS]

STALE = ("python -m cli.", "python -m agent.", "python -m broker",
         "./scripts/demo.sh", "broker/backends.py")

# policies/authz.rego moved -- it did not get renamed. Task 20 put it at
# warden/policies/authz.rego, so the plain substring "policies/authz.rego"
# is present in BOTH the stale bare path and the correct, current one (the
# correct one simply has "warden/" in front of it). A plain `in` check like
# the five needles above use cannot tell "still says the old top-level
# policies/ directory" from "says the new path, which happens to end the
# same way" -- it would flag every correct mention forever. Only a match
# NOT immediately preceded by "warden/" is genuinely the old, unprefixed
# path, so this one needle gets a regex with a negative lookbehind instead
# of joining the tuple above.
STALE_POLICY_PATH = re.compile(r"(?<!warden/)policies/authz\.rego")


@pytest.mark.parametrize("doc", CURRENT_DOCS, ids=lambda p: p.name)
def test_no_stale_invocation_or_path(doc):
    text = doc.read_text()
    offenders = [needle for needle in STALE if needle in text]
    if STALE_POLICY_PATH.search(text):
        offenders.append("policies/authz.rego (not under warden/)")
    assert offenders == [], offenders


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_referenced_repo_path_exists(doc):
    missing = []
    for match in re.findall(r"\[[^\]]*\]\(((?!https?:)[^)#]+)", doc.read_text()):
        target = (doc.parent / match).resolve()
        if not target.exists():
            missing.append(match)
    assert missing == []


def test_the_readme_replay_block_matches_the_golden():
    """The block README showcases must be the one the frozen log produces."""
    golden = (REPO_ROOT / "tests" / "golden" / "replay-4711.txt").read_text()
    block = re.search(r"```\n(task 4711.*?)\n```", (REPO_ROOT / "README.md").read_text(),
                      re.S).group(1)
    mask = lambda s: re.sub(r"head sha256:[0-9a-f…]*", "head sha256:…", s)
    assert mask(block).splitlines() == mask(golden.rstrip("\n")).splitlines()


@pytest.mark.parametrize("doc", sorted(DATED_WRITE_UPS), ids=lambda n: n)
def test_the_dated_write_up_says_it_is_dated(doc):
    """The exclusion above is a scoping decision, not a silent hole: each
    dated write-up must actually carry a note, near the top, explaining that
    its commands are historical and giving today's equivalents -- or the
    exclusion has nothing backing it."""
    head = (REPO_ROOT / "docs" / doc).read_text()[:1000].lower()
    assert "2026-07-30" in head
    assert "today" in head
