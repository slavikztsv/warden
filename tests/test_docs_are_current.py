"""Docs that name a path or a command must name one that exists."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = [REPO_ROOT / "README.md", *(REPO_ROOT / "docs").glob("*.md")]

# Every doc is in scope for the stale-invocation scan below, with nothing
# skipped by name. Two dated live-run write-ups used to be exempt, on the
# argument that their commands were true on the day they were written and
# that rewriting them would falsify a historical record. That exemption is
# exactly what let `warden-demo up --profile guarded` survive inside one of
# those files' own "today's equivalent" notes long after the profile was
# renamed to `protected` -- a command that errors, in the sentence telling
# the reader what to run instead. Both files have since been removed, and
# the lesson is kept: a document nothing checks is a document that rots.
CURRENT_DOCS = DOCS

STALE = ("python -m cli.", "python -m agent.", "python -m broker",
         "./scripts/demo.sh", "broker/backends.py",
         # requirements.txt became requirements-dev.txt when its four runtime
         # pins turned out to be a byte-identical restatement of
         # warden/pyproject.toml's, leaving two files pinning the same versions
         # and nothing saying which won. Six source comments named the old file
         # to mean "not a declared dependency", and nothing would have caught
         # them going stale -- the same gap that let broker/app.py survive in
         # five comments after the decision sequence moved to broker/spine.py.
         # Safe as a bare substring: "requirements-live.txt" does not contain
         # it, because the "requirements" there is followed by "-live".
         "requirements.txt")

# policies/authz.rego moved -- it did not get renamed. Task 20 put it at
# warden/policies/authz.rego, so the plain substring "policies/authz.rego"
# is present in BOTH the stale bare path and the correct, current one (the
# correct one simply has "warden/" in front of it). A plain `in` check like
# the five needles above use cannot tell "still says the old top-level
# policies/ directory" from "says the new path, which happens to end the
# same way" -- it would flag every correct mention forever. Only a match
# NOT immediately preceded by "warden/" is genuinely the old, unprefixed
# path, so this one needle gets a regex with a negative lookbehind instead
# of joining the tuple above. Also not preceded by "/": the CONTAINER mount
# path (compose.yml binds warden/policies/authz.rego to /policies/authz.rego)
# is a third, equally-current spelling that source comments use and docs
# never happened to -- excluded here rather than after the fact.
STALE_POLICY_PATH = re.compile(r"(?<!warden/)(?<!/)policies/authz\.rego")


@pytest.mark.parametrize("doc", CURRENT_DOCS, ids=lambda p: p.name)
def test_no_stale_invocation_or_path(doc):
    text = doc.read_text()
    offenders = [needle for needle in STALE if needle in text]
    if STALE_POLICY_PATH.search(text):
        offenders.append("policies/authz.rego (not under warden/)")
    assert offenders == [], offenders


# --- The same scan, over source comments -----------------------------------
#
# This codebase's comments are load-bearing documentation: several of them
# name specific files (docker-compose.yml, cli/warden.py, scripts/demo.sh)
# that this branch deleted or renamed, discovered only by hand-grepping
# during a whole-branch review. Running the same stale-reference scan over
# warden/**/*.py and demo/**/*.py -- not just the top-level docs -- is what
# keeps that from recurring silently. Two additions apply only here: docs
# never happened to mention either deleted/renamed path, so adding them to
# the shared STALE tuple above would not change docs coverage, only widen
# what source comments are held to.
SOURCE_STALE = (*STALE, "docker-compose.yml", "cli/warden.py")


def source_files() -> list[Path]:
    return [
        p for tree in ("warden", "demo") for p in (REPO_ROOT / tree).rglob("*.py")
        if "__pycache__" not in p.parts and "egg-info" not in p.parts
    ]


@pytest.mark.parametrize("path", source_files(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_no_stale_invocation_or_path_in_source_comments(path):
    text = path.read_text()
    offenders = [needle for needle in SOURCE_STALE if needle in text]
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
    def mask(s):
        return re.sub(r"head sha256:[0-9a-f…]*", "head sha256:…", s)
    assert mask(block).splitlines() == mask(golden.rstrip("\n")).splitlines()


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_embedded_image_exists(doc):
    """An <img src> names a path the same way a [link](path) does.

    test_every_referenced_repo_path_exists only matches markdown link syntax,
    so the README's diagrams -- which are all raw <img> tags, because they need
    a width attribute -- were never covered. A renamed or unrendered asset
    showed as a broken image on the project's front page and nothing failed.
    """
    missing = [
        src for src in re.findall(r'<img[^>]+src="((?!https?:)[^"]+)"', doc.read_text())
        if not (doc.parent / src).resolve().exists()
    ]
    assert missing == []


def test_every_stopped_scenario_has_its_illustration_and_the_reverse():
    """The "What it stops" table and the strip above it must agree.

    They are written by hand from the same run, in the same order, and the
    table gained four scenarios before the illustrations existed. A row with no
    strip reads as an omission; a strip with no row is a claim with no figure
    behind it.
    """
    readme = (REPO_ROOT / "README.md").read_text()
    section = readme.split("## What it stops")[1].split("## Quick start")[0]

    illustrated = re.findall(r'<img src="docs/assets/stop-([a-z-]+)\.png"', section)
    tabled = re.findall(r"^\| `([a-z-]+)` \|", section, re.M)

    assert illustrated == tabled, (
        f"illustrations {illustrated} do not match table rows {tabled}"
    )
    # And each one is a scenario the demo can actually run, not a name only the
    # README knows.
    from demo.cli.explain import TASKS

    assert [name for name in tabled if name not in TASKS] == []
