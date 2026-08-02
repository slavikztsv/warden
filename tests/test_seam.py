"""The seam, as a test rather than a convention.

pip already enforces the dependency direction. These assert the rest: that
the product tree holds no scenario knowledge, that the product boots knowing
no tools, and that the enforcement point holds nothing that can sign.

warden/policies/data.json used to be a named, expiring exception to the
scenario-string scan: real demo configuration (purpose "support-triage",
host "docstore.internal", the four demo tool names) sitting inside the
product tree, because OPA mounted ./warden/policies as ONE directory and
moving data.json out from under it would have broken that mount. Task 22
splits the mount into file-level binds and moves data.json to
demo/scenario/ alongside tools.toml, warden.toml and control.toml -- where
the design always put it -- so the exception is gone rather than renamed:
the scan below now covers every file in the product tree, no carve-out
required.
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
    # "demo/", not "demo/scenario" and not bare "demo". The property this
    # scan exists to hold is "no file under warden/ references a demo path"
    # -- not merely "no file references demo/scenario" -- so a needle scoped
    # to that one subdirectory would miss a reference to, say, demo/cli or
    # demo/agent and still let the scan report clean. Bare "demo" goes the
    # other way: it matches ordinary English ("the demo shows...", "exists
    # to demonstrate") throughout warden/'s own docstrings, which would force
    # this scan into exception-ridden uselessness just to keep passing --
    # exactly the rot a scan exists to avoid. "demo/" -- the substring that
    # only appears when a real filesystem path into the demo tree is being
    # named -- is the narrowest needle that still pins the actual property.
    # It is what would have caught `warden config check` shipping
    # `--catalog demo/scenario/tools.toml` as its own default: that value is
    # exactly this shape, and no other needle above happens to overlap it.
    "demo/",
)

# The full set of extensions the scan below considers, named once so a
# reader sees it at a glance instead of piecing it together from separate
# globs. Adding a new source language to warden/ means adding it here.
SCANNED_EXTENSIONS = (".py", ".rego", ".toml", ".json")


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
    with an extension in SCANNED_EXTENSIONS, minus the OPA test-fixture
    exclusion above (_is_opa_test_fixture)."""
    return [
        p for p in PRODUCT.rglob("*")
        if p.is_file()
        and p.suffix in SCANNED_EXTENSIONS
        and "__pycache__" not in p.parts
        and not _is_opa_test_fixture(p)
    ]


def product_sources() -> list[Path]:
    return [p for p in product_files() if p.suffix == ".py"]


@pytest.mark.parametrize("needle", SCENARIO_STRINGS)
def test_the_product_tree_holds_no_scenario_string(needle):
    """No scenario knowledge in the product tree, full stop.

    Used to read "unexcepted": warden/policies/data.json genuinely failed
    this property, and was excluded by name rather than by the test
    silently not looking. Task 22 moved data.json to demo/scenario/, so the
    scan now covers every file product_files() considers with no carve-out
    to keep honest.
    """
    offenders = [
        f"{p.relative_to(REPO_ROOT)}"
        for p in product_files()
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


def test_the_broker_dockerfile_copies_no_demo_path():
    """warden/Dockerfile's own comment claims this: "tests/test_seam.py's
    Dockerfile check asserts no COPY line here mentions demo either." That
    claim named a test that did not exist -- the Dockerfile itself was
    correct, but an assertion nobody makes true is worse than no comment at
    all. This is that test."""
    copy_lines = [
        line for line in (REPO_ROOT / "warden" / "Dockerfile").read_text().splitlines()
        if line.strip().startswith("COPY")
    ]
    assert copy_lines, "no COPY lines found -- the scan below would pass vacuously"
    assert not any("demo" in line for line in copy_lines), copy_lines


def test_a_catalog_tool_without_an_args_table_refuses_to_load(tmp_path):
    from warden.broker.config.catalog import load_catalog
    from warden.broker.config.loader import ConfigError

    manifest = tmp_path / "tools.toml"
    manifest.write_text('[tools.t]\nkind = "http"\n[tools.t.binding]\n')
    with pytest.raises(ConfigError, match="args"):
        load_catalog(manifest, env={}, client=None)


# --- Task 22: two images, two compose files ---------------------------------


def test_the_demo_compose_never_redefines_a_product_service():
    """The overlay may not redefine what a product service (broker,
    broker-control, opa) builds from, exposes, or runs -- compose.yml is the
    single source of truth for that, and re-declaring it here would let a
    demo-only file silently change product behaviour.

    It MAY extend `broker`'s depends_on: Compose merges depends_on lists
    across files by service key rather than replacing them, so the overlay
    adding `docstore` and `mailer` here is what lets compose.yml's own
    `depends_on: [opa]` stay valid on its own (compose.yml's own comment
    explains why docstore/mailer cannot live in the base file at all). That
    is the only shape a product-service stanza may take in this file: a bare
    depends_on and nothing else -- no build, no image, no command, no
    networks.
    """
    import re

    overlay = (REPO_ROOT / "demo" / "compose.demo.yml").read_text()
    for service in ("broker:", "broker-control:", "opa:"):
        match = re.search(
            rf"^  {re.escape(service)}\n(.*?)(?=^  \S|\Z)", overlay, re.M | re.S
        )
        if match is None:
            continue
        lines = [
            line for line in match.group(1).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert lines, service
        assert all(re.match(r"^\s+depends_on:\s*\[", line) for line in lines), (
            service, lines
        )


def test_the_product_compose_keeps_the_protected_profile():
    """Without it, `--profile unprotected` starts the enforcement point, and
    'the broker is not running' is how README and THREAT_MODEL describe the
    control case."""
    import re

    base = (REPO_ROOT / "compose.yml").read_text()
    for service in ("opa", "broker", "broker-control"):
        # A plain str.split("\n  ") boundary matches the very next line
        # regardless of its indentation depth -- every nested property line
        # in block-style YAML starts with two-or-more spaces too, so that
        # split point lands immediately after the service key and the
        # "block" it captures is always empty. Anchoring the closing
        # boundary to a line starting at exactly two spaces (the next
        # top-level service key, `^  \S`) is what actually isolates one
        # service's own body.
        match = re.search(
            rf"^  {re.escape(service)}:\n(.*?)(?=^  \S|\Z)", base, re.M | re.S
        )
        assert match, service
        block = match.group(1)
        assert "profiles: [protected]" in block, service
