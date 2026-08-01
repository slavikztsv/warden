"""The seam, as a test rather than a convention.

pip already enforces the dependency direction. These assert the rest: that no
scenario knowledge survives in the product tree, that the product boots
knowing no tools, and that the enforcement point holds nothing that can sign.
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


def product_sources() -> list[Path]:
    return [p for p in PRODUCT.rglob("*.py") if "__pycache__" not in p.parts]


def product_rego() -> list[Path]:
    """The shipped policy, not its own test suite.

    OPA's `opa test` discovers a test by name convention (any rule prefixed
    `test_`), which requires the test file to sit BESIDE the rego it exercises
    -- there is no `tests/` directory it could move to the way every Python
    test in this repo already has. warden/policies/authz_test.rego is that
    file: test-only code that happens to be forced to live in the product
    tree by OPA's own tooling, not product source that ships. Its final
    section deliberately evaluates the REAL warden/policies/data.json (not a
    mock) -- see its own "Shipped-configuration tests" comment -- so the
    purpose name and host it names there ("support-triage",
    "docstore.internal") are not narrative choices this test could reword
    without either breaking that real-bundle coverage or rewriting
    data.json's actual content, which is a deployment-config question this
    task does not decide. Excluded the same way tests/*.py already is by
    directory structure; authz.rego itself (the actual policy) is scanned
    and is clean but for two comments, fixed alongside this test.
    """
    return [p for p in PRODUCT.rglob("*.rego") if not p.name.endswith("_test.rego")]


@pytest.mark.parametrize("needle", SCENARIO_STRINGS)
def test_the_product_tree_holds_no_scenario_string(needle):
    offenders = [
        f"{p.relative_to(REPO_ROOT)}"
        for p in [*product_sources(), *product_rego(), *PRODUCT.rglob("*.toml")]
        if needle in p.read_text()
    ]
    assert offenders == []


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
