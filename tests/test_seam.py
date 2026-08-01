"""The seam, as a test rather than a convention.

pip already enforces the dependency direction. These assert the rest: that
the product tree holds no scenario knowledge -- with one named, expiring
exception, warden/policies/data.json (see DATA_JSON_EXCEPTION and
test_the_data_json_scenario_exception_has_not_gone_stale below) -- that the
product boots knowing no tools, and that the enforcement point holds nothing
that can sign.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PRODUCT = REPO_ROOT / "warden"

SCENARIO_STRINGS = (
    "4711", "8812", "attacker.example", "docstore.internal",
    "support-triage", "triage-bot", "refund", "customers",
)

# The full set of extensions the scan below considers, named once so a
# reader sees it at a glance instead of piecing it together from separate
# globs. Adding a new source language to warden/ means adding it here.
SCANNED_EXTENSIONS = (".py", ".rego", ".toml", ".json")

# Named exceptions to the scan -- not silent gaps. Each one says what the
# file is, why it is excluded today, and (where applicable) what closes the
# exception.
#
# warden/policies/data.json ships the demo's real configuration --
# purpose "support-triage", host "docstore.internal", and all four demo
# tool names -- inside the product tree. That is genuine scenario
# knowledge, and unlike authz_test.rego (excluded below for a different,
# permanent reason) there is no argument that it doesn't ship: it is the
# exact file docker-compose.yml mounts into the OPA container today.
# It is here, and not under demo/scenario/ alongside tools.toml /
# warden.toml / control.toml where the design puts it, because OPA
# currently mounts ./warden/policies as ONE directory -- moving data.json
# out from under it breaks that mount. Task 22 splits the mount into
# file-level binds and moves data.json out at the same time (see its own
# plan section); test_the_data_json_scenario_exception_has_not_gone_stale
# below fails the moment that happens, so this exception cannot quietly
# outlive its reason.
DATA_JSON_EXCEPTION = PRODUCT / "policies" / "data.json"


def _is_opa_test_fixture(path: Path) -> bool:
    """True for warden/policies/authz_test.rego and anything shaped like it.

    OPA's `opa test` discovers a test by name convention (any rule prefixed
    `test_`), which requires the test file to sit BESIDE the rego it
    exercises -- there is no `tests/` directory it could move to the way
    every Python test in this repo already has. This is test-only code
    forced to live in the product tree by OPA's own tooling, not product
    source that ships: Task 22's compose mounts only authz.rego and
    data.json, never this file. Its "shipped-configuration tests" section
    deliberately evaluates the REAL data.json (not a mock) -- see its own
    comment -- so the purpose name and host it names there
    ("support-triage", "docstore.internal") are not narrative choices this
    scan could reword without breaking that real-bundle coverage. Excluded
    the same way tests/*.py already is by directory structure, permanently
    (there is no task that moves it, because it cannot move). authz.rego
    itself (the actual policy) is scanned and is clean but for two
    comments, fixed alongside this test.
    """
    return path.name.endswith("_test.rego")


def product_files() -> list[Path]:
    """Every warden/ file the scenario-string scan considers: everything
    with an extension in SCANNED_EXTENSIONS, minus the two named exceptions
    above (_is_opa_test_fixture, DATA_JSON_EXCEPTION)."""
    return [
        p for p in PRODUCT.rglob("*")
        if p.is_file()
        and p.suffix in SCANNED_EXTENSIONS
        and "__pycache__" not in p.parts
        and not _is_opa_test_fixture(p)
        and p != DATA_JSON_EXCEPTION
    ]


def product_sources() -> list[Path]:
    return [p for p in product_files() if p.suffix == ".py"]


@pytest.mark.parametrize("needle", SCENARIO_STRINGS)
def test_the_product_tree_holds_no_unexcepted_scenario_string(needle):
    """No scenario knowledge outside the named exceptions above.

    Not "no scenario knowledge, full stop": warden/policies/data.json
    genuinely fails this property today (see DATA_JSON_EXCEPTION) and is
    excluded by name rather than by the test silently not looking -- the
    exclusion is spelled out above, and the next test asserts the exclusion
    is still honest.
    """
    offenders = [
        f"{p.relative_to(REPO_ROOT)}"
        for p in product_files()
        if needle in p.read_text()
    ]
    assert offenders == []


def test_the_data_json_scenario_exception_has_not_gone_stale():
    """Forces DATA_JSON_EXCEPTION to be deleted the moment it stops being
    true, rather than letting the scan quietly not-scan a file that no
    longer needs the exception.

    Task 22 moves warden/policies/data.json to demo/scenario/ alongside
    tools.toml, warden.toml and control.toml (splitting OPA's single-
    directory mount into file-level binds is what makes the move safe).
    The moment that happens, this file will not exist here, this test will
    fail, and whoever is there must delete this test and
    DATA_JSON_EXCEPTION together -- at which point
    test_the_product_tree_holds_no_unexcepted_scenario_string starts
    scanning data.json for real, with nothing left to hide behind.
    """
    assert DATA_JSON_EXCEPTION.exists(), (
        f"{DATA_JSON_EXCEPTION} is gone -- delete DATA_JSON_EXCEPTION and "
        "this test, the scenario-string scan can cover it directly now"
    )


def test_no_product_module_imports_the_demo():
    offenders = []
    for path in product_sources():
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(n == "demo" or n.startswith("demo.") for n in names):
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_the_product_tree_ships_no_tool_catalog():
    """The product boots knowing no tools.

    `warden serve` takes no default catalog of its own: warden.toml's
    [catalog].tools names a path the DEPLOYMENT supplies (see
    warden/broker/config/loader.py) -- demo/scenario/tools.toml, for this
    repo's own demo, mounted in from outside the product tree. A tools.toml
    living inside warden/ would be exactly the scenario knowledge this seam
    keeps out, and today there is none: this is the stronger, already-true
    form of "ships an empty reference catalog" (the commented, zero-tool
    warden/reference/tools.toml a later task adds as a template) -- no
    catalog file to declare tools with at all, anywhere in the tree.

    NOTE for whoever adds warden/reference/tools.toml: that file is
    supposed to exist and declare zero tools, not fail to exist. When it
    lands, loosen this to "the catalog it finds declares no tools"
    (tomllib-parse it and assert `.get("tools", {}) == {}`, as
    test_the_reference_catalog_declares_no_tools does in the wider plan)
    rather than deleting the test outright.
    """
    catalogs = [p for p in PRODUCT.rglob("*.toml") if p.name == "tools.toml"]
    assert catalogs == []


def test_serve_reaches_no_signer():
    """The property broker/__main__.py's docstring states, as a transitive
    assertion over the module graph `warden serve` actually pulls in.

    It is about the address space, not the filesystem: serve and control
    share a binary, and `warden control` legitimately imports Signer. So the
    walk starts at the serve entrypoint alone and follows only imports within
    the warden package.

    The walk is necessarily approximate: `from pkg.mod import Name` cannot be
    told, by AST alone, from `from pkg import submodule` -- so both
    `pkg.mod` and `pkg.mod.Name` are queued, and the latter routinely is not
    an importable module at all (a class, a function). That failure is
    expected and is not evidence of anything; it is skipped rather than
    treated as a walk error. The load-bearing assertion is the one inside the
    loop, run against every module the walk DOES resolve.
    """
    import warden.cli.main as cli

    seen: set[str] = set()
    stack = [cli.SERVE_ENTRYPOINT]
    while stack:
        name = stack.pop()
        if name in seen or not name.startswith("warden"):
            continue
        seen.add(name)
        try:
            module = importlib.import_module(name)
        except ImportError:
            # Not actually a module -- almost always the "pkg.mod.Name" guess
            # above resolving to a class or function instead. Nothing to walk.
            continue
        tree = ast.parse(Path(module.__file__).read_text())
        referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        referenced |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                referenced |= {a.name for a in node.names}
                stack.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                referenced |= {a.name for a in node.names}
                stack.append(node.module)
                stack.extend(f"{node.module}.{a.name}" for a in node.names)
        assert "Signer" not in referenced, f"{name} reaches Signer"
    assert seen, "walked no modules -- SERVE_ENTRYPOINT is wrong"


def test_a_catalog_tool_without_an_args_table_refuses_to_load(tmp_path):
    from warden.broker.config.catalog import load_catalog
    from warden.broker.config.loader import ConfigError

    manifest = tmp_path / "tools.toml"
    manifest.write_text('[tools.t]\nkind = "http"\n[tools.t.binding]\n')
    with pytest.raises(ConfigError, match="args"):
        load_catalog(manifest, env={}, client=None)
