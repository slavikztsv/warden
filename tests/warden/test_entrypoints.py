"""The key split, tested at the wiring level.

The claim these guard: *the agent cannot expand its own authority*. That claim
used to be false. broker/__main__.py called Signer.generate() and served
create_control_app() on 0.0.0.0:8081 from the same container that is attached
to agent-net, and the control app has no authentication and lets its caller
choose task_id, purpose, allowed_tools and counterparties. Anything on
agent-net could therefore mint itself an unlimited token -- and, by naming a
fresh task_id, reset the taint state and the row budget with it.

The fix is topological, so most of it can only be verified by inspection (no
Docker here). What IS mechanically testable is the part these tests cover:

  * the broker process constructs a Verifier from a public-key FILE,
  * that process holds no signing key and exposes no minting route,
  * the control entrypoint loads the private key and mints tokens the
    broker's verifier accepts -- i.e. the split keypair really is one keypair.

A second claim joined these once build() moved from an untyped env dict to a
parsed BrokerConfig / ControlConfig: two functions with different signatures,
neither taking **kwargs, used to be splatted from the same dict, so nothing
stopped a new key from breaking one of them silently. That is now
`broker.wiring.BrokerComponents`, typed and covered below.
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import warden.broker.__main__ as broker_main
import warden.broker.control_main as control_main
from warden.broker.config.loader import BrokerConfig, ControlConfig, load_broker_config, load_control_config
from warden.broker.identity import Signer, Verifier
from demo.mocks.seed_db import seed_customers

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def write_keypair(directory: Path) -> tuple[Path, Path]:
    """Generates a keypair to two files, the way `warden-demo up`'s
    `_generate_keypair` (demo/cli/main.py) does."""
    key = Ed25519PrivateKey.generate()
    private_path = directory / "agent.key"
    public_path = directory / "agent.pub"
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def write_warden_toml(
    tmp_path: Path,
    public_key: Path,
    *,
    bundle_roots: list[Path] | None = None,
    audit_path: Path | None = None,
    catalog_tools: Path | None = None,
    opa_url: str = "http://opa:8181",
    decision_path: str = "warden/authz",
    issuer: str = "warden-broker",
    listen: str = "0.0.0.0:8080",
    proxy_listen: str = "0.0.0.0:3128",
) -> Path:
    """Writes a warden.toml the shape compose.yml mounts, with the
    same defaults broker_env() used to bake into an env dict -- one root
    policy bundle, one tool manifest, the demo's real backends.

    No ttl_seconds: the broker verifies a token's issuer but never mints, so
    [tokens] here carries issuer only -- a TTL would be parsed and never
    consumed. See write_control_toml for where ttl_seconds actually lives.
    """
    bundle_roots = bundle_roots or [REPO_ROOT / "warden" / "policies"]
    audit_path = audit_path or (tmp_path / "audit.jsonl")
    catalog_tools = catalog_tools or (REPO_ROOT / "demo" / "scenario" / "tools.toml")
    roots_toml = ", ".join(f'"{root}"' for root in bundle_roots)
    path = tmp_path / "warden.toml"
    path.write_text(f"""
[broker]
listen       = "{listen}"
proxy_listen = "{proxy_listen}"

[identity]
public_key = "{public_key}"

[policy]
opa_url       = "{opa_url}"
decision_path = "{decision_path}"
bundle_roots  = [{roots_toml}]

[audit]
path = "{audit_path}"

[tokens]
issuer = "{issuer}"

[catalog]
tools = "{catalog_tools}"
""")
    return path


def broker_config(tmp_path: Path, public_key: Path, **kwargs) -> BrokerConfig:
    return load_broker_config(write_warden_toml(tmp_path, public_key, **kwargs), env={})


def write_control_toml(
    tmp_path: Path,
    private_key: Path,
    *,
    listen: str = "0.0.0.0:8081",
    issuer: str = "warden-broker",
    ttl_seconds: int = 300,
) -> Path:
    """issuer here must match write_warden_toml's issuer for a token minted
    under one to verify under the other -- see
    test_a_configured_issuer_mismatch_is_rejected_end_to_end. ttl_seconds is
    control-plane-only: the broker's config has no such field."""
    path = tmp_path / "control.toml"
    path.write_text(f"""
[control]
listen = "{listen}"

[identity]
private_key = "{private_key}"

[tokens]
issuer      = "{issuer}"
ttl_seconds = {ttl_seconds}
""")
    return path


def control_config(tmp_path: Path, private_key: Path, **kwargs) -> ControlConfig:
    return load_control_config(write_control_toml(tmp_path, private_key, **kwargs), env={})


def set_catalog_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """build() interpolates demo/scenario/tools.toml's ${DOCSTORE_URL},
    ${DB_PATH} and ${MAILER_URL} straight from the real process environment
    -- the same three values compose.yml sets on the broker service --
    not from the parsed config. Every test that calls broker_main.build()
    needs these set for the duration of the call."""
    seed_customers(tmp_path / "customers.db", count=5)
    monkeypatch.setenv("DOCSTORE_URL", "http://docstore.internal")
    monkeypatch.setenv("MAILER_URL", "http://mailer.internal")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "customers.db"))


def stub_client() -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x")))


# --- The broker process: verifies, never mints -----------------------------


def test_broker_wiring_builds_a_verifier_from_a_public_key_file(tmp_path, monkeypatch):
    private_path, public_path = write_keypair(tmp_path)
    set_catalog_env(monkeypatch, tmp_path)
    config = broker_config(tmp_path, public_path)
    _, components = broker_main.build(config, client=stub_client())

    assert isinstance(components.verifier, Verifier)
    # It is the right key, not merely a Verifier-shaped object: a token minted
    # by the private half of the same pair must verify.
    token = Signer.from_private_key_file(private_path).mint(
        agent_id="triage-bot", task_id="4711", purpose="support-triage",
        allowed_tools=["read_document"], data_classes=["public"],
        counterparties=["customer:8812"],
    )
    assert components.verifier.verify(token).task_id == "4711"


def test_broker_verifier_rejects_a_token_from_any_other_key(tmp_path, monkeypatch):
    """Negative control for the test above: the verifier is bound to that one
    public key, so a token minted anywhere else -- including by a Signer the
    broker might once have generated for itself -- is refused."""
    from warden.broker.identity import TokenInvalid

    _, public_path = write_keypair(tmp_path)
    set_catalog_env(monkeypatch, tmp_path)
    config = broker_config(tmp_path, public_path)
    _, components = broker_main.build(config, client=stub_client())

    foreign = Signer.generate().mint(
        agent_id="triage-bot", task_id="4711", purpose="support-triage",
        allowed_tools=["read_document", "query_customers", "http_fetch", "send_email"],
        data_classes=["pii"], counterparties=["attacker@evil.example"],
    )
    with pytest.raises(TokenInvalid):
        components.verifier.verify(foreign)


def test_broker_process_holds_no_signing_key(tmp_path, monkeypatch):
    """The enforcement point is the service the agent can reach, so it is the
    service most exposed to a subverted agent. It must hold no material that
    can sign a token: not a Signer, not an Ed25519 private key, anywhere in
    the objects it wires up."""
    _, public_path = write_keypair(tmp_path)
    set_catalog_env(monkeypatch, tmp_path)
    config = broker_config(tmp_path, public_path)
    app, components = broker_main.build(config, client=stub_client())

    def reachable_objects(root, seen=None, depth=0):
        if seen is None:
            seen = set()
        if depth > 4 or id(root) in seen:
            return
        seen.add(id(root))
        yield root
        values = root.values() if isinstance(root, dict) else []
        items = list(root) if isinstance(root, (list, tuple, set)) else []
        attrs = getattr(root, "__dict__", {}).values()
        for child in [*values, *items, *attrs]:
            yield from reachable_objects(child, seen, depth + 1)

    for obj in reachable_objects({"app": app, "components": components}):
        assert not isinstance(obj, Signer), "the broker wired up a Signer"
        assert not isinstance(obj, Ed25519PrivateKey), "the broker holds a private key"


def test_broker_entrypoint_source_never_names_the_signer():
    """Structural, not behavioural: even an unexecuted branch that reaches for
    Signer in this module would reintroduce the escalation path, so assert the
    name does not appear in the module at all. Signer.generate() lived here."""
    source = (REPO_ROOT / "warden" / "broker" / "__main__.py").read_text()
    tree = ast.parse(source)
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= {alias.name for alias in node.names}
    assert "Signer" not in names
    assert "create_control_app" not in names


def test_broker_app_exposes_no_minting_route(tmp_path, monkeypatch):
    _, public_path = write_keypair(tmp_path)
    set_catalog_env(monkeypatch, tmp_path)
    config = broker_config(tmp_path, public_path)
    app, _ = broker_main.build(config, client=stub_client())

    assert not any("token" in route.path for route in app.routes)
    assert TestClient(app).post("/v1/tokens", json={}).status_code == 404


def test_broker_refuses_to_start_without_the_public_key(tmp_path, monkeypatch):
    """Fail closed at startup. A broker that came up with no verification key
    would have to either trust everything or reject everything, and finding
    out which at request time is not acceptable for an enforcement point."""
    set_catalog_env(monkeypatch, tmp_path)
    config = broker_config(tmp_path, tmp_path / "absent.pub")
    with pytest.raises(FileNotFoundError):
        broker_main.build(config, client=stub_client())


def test_broker_refuses_a_public_key_file_that_is_not_ed25519(tmp_path, monkeypatch):
    _, public_path = write_keypair(tmp_path)
    public_path.write_bytes(b"-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n")
    set_catalog_env(monkeypatch, tmp_path)
    config = broker_config(tmp_path, public_path)
    with pytest.raises(Exception):
        broker_main.build(config, client=stub_client())


def test_broker_wiring_digests_every_policy_path_root(tmp_path, monkeypatch):
    """bundle_roots may name more than one root -- this is the one production
    entry point the whole policy_bundle_digest signature change exists for. A
    bundle split across a rules root and a data root must be digested as one,
    so changing a file in the SECOND root must change the digest the broker
    wires up at startup. The previous single-directory digest would have
    silently ignored a second root: max_rows_per_task 50 -> 5,000,000 with
    every audit record still claiming the identical policy."""
    _, public_path = write_keypair(tmp_path)
    set_catalog_env(monkeypatch, tmp_path)

    rules_root = tmp_path / "policy_rules"
    data_root = tmp_path / "policy_data"
    rules_root.mkdir()
    data_root.mkdir()
    (rules_root / "authz.rego").write_text("package warden.authz\n")
    (data_root / "data.json").write_text('{"limits": {"max_rows_per_task": 50}}\n')

    config = broker_config(tmp_path, public_path, bundle_roots=[rules_root, data_root])

    _, components_before = broker_main.build(config, client=stub_client())

    (data_root / "data.json").write_text('{"limits": {"max_rows_per_task": 5000000}}\n')

    _, components_after = broker_main.build(config, client=stub_client())

    assert components_before.policy_digest != components_after.policy_digest


# --- Typed wiring: one object, two shapes -----------------------------------


def test_wiring_is_typed_so_a_new_component_cannot_break_the_proxy():
    """deps was an untyped dict splatted into two functions with different
    signatures, neither taking **kwargs. Adding one key -- the catalog, which
    create_app needs and authorize_connect does not -- raised TypeError from
    serve_proxy and took all egress down. No grep for a literal finds that."""
    import inspect

    from warden.broker.app import create_app
    from warden.broker.proxy import authorize_connect
    from warden.broker.wiring import BrokerComponents

    app_params = set(inspect.signature(create_app).parameters)
    proxy_params = set(inspect.signature(authorize_connect).parameters)
    stub = BrokerComponents(verifier=None, pdp=None, taint=None, audit=None,
                            policy_digest="sha256:x")
    # Exactly the shared components, no more and no less -- a subset check
    # alone would pass just as happily if either method returned {}.
    expected = {"verifier", "pdp", "taint", "audit", "policy_digest"}
    assert set(stub.as_app_kwargs()) == expected
    assert set(stub.as_proxy_kwargs()) == expected
    assert expected <= app_params
    assert expected <= proxy_params


def test_the_entrypoint_reads_a_toml_config(tmp_path, monkeypatch):
    _, public_path = write_keypair(tmp_path)
    set_catalog_env(monkeypatch, tmp_path)
    (tmp_path / "warden.toml").write_text(f"""
[broker]
listen = "0.0.0.0:8080"
proxy_listen = "0.0.0.0:3128"
[identity]
public_key = "{public_path}"
[policy]
opa_url = "http://opa:8181"
decision_path = "warden/authz"
bundle_roots = ["warden/policies"]
[audit]
path = "{tmp_path / 'audit.jsonl'}"
[tokens]
issuer = "warden-broker"
[catalog]
tools = "demo/scenario/tools.toml"
""")
    config = load_broker_config(tmp_path / "warden.toml", env={
        "DOCSTORE_URL": "http://d", "DB_PATH": "data/customers.db",
        "MAILER_URL": "http://m",
    })
    app, components = broker_main.build(config, client=stub_client())
    assert components.policy_digest.startswith("sha256:")


# --- The control process: the only minter ----------------------------------
#
# The two tests below prove the [tokens] wiring is live end to end, through
# the real entrypoints -- not just at broker/identity.py's unit level -- so a
# regression that reintroduced the hardcoded ISSUER/DEFAULT_TTL_SECONDS
# constants at either build() would show up here even if identity.py's own
# tests kept passing.


def test_a_configured_issuer_mismatch_is_rejected_end_to_end(tmp_path, monkeypatch):
    """warden.toml's [tokens].issuer and control.toml's [tokens].issuer must
    agree, or every token fails. Built through control_main.build() and
    broker_main.build() -- the real entrypoints -- not through Signer/Verifier
    directly, so this also proves both build()s actually pass config.issuer
    through rather than falling back to the shared module constant."""
    from warden.broker.identity import TokenInvalid

    private_path, public_path = write_keypair(tmp_path)

    control_app = control_main.build(
        control_config(tmp_path, private_path, issuer="control-plane-a")
    )
    response = TestClient(control_app).post(
        "/v1/tokens",
        json={
            "agent_id": "triage-bot", "task_id": "4711", "purpose": "support-triage",
            "allowed_tools": ["read_document"], "data_classes": ["public"],
            "counterparties": ["customer:8812"],
        },
    )
    assert response.status_code == 200

    set_catalog_env(monkeypatch, tmp_path)
    _, components = broker_main.build(
        broker_config(tmp_path, public_path, issuer="control-plane-b"), client=stub_client()
    )
    with pytest.raises(TokenInvalid):
        components.verifier.verify(response.json()["token"])


def test_control_toml_ttl_seconds_reaches_the_minted_token(tmp_path):
    """A ttl_seconds in control.toml that differs from DEFAULT_TTL_SECONDS
    must change the minted token's actual expiry -- checked against the
    decoded claim (via jwt, bypassing our own Verifier's issuer/exp checks),
    not against the constant, and via the real HTTP mint route rather than
    calling Signer.mint() directly."""
    import jwt

    private_path, _ = write_keypair(tmp_path)
    before = int(time.time())

    control_app = control_main.build(control_config(tmp_path, private_path, ttl_seconds=3600))
    response = TestClient(control_app).post(
        "/v1/tokens",
        json={
            "agent_id": "triage-bot", "task_id": "4711", "purpose": "support-triage",
            "allowed_tools": ["read_document"], "data_classes": ["public"],
            "counterparties": ["customer:8812"],
        },
    )
    assert response.status_code == 200
    claims = jwt.decode(response.json()["token"], options={"verify_signature": False})

    # Close to before+3600, not anywhere near before+300 (the old default).
    assert abs(claims["exp"] - (before + 3600)) < 10
    assert claims["exp"] - before > 1000


def test_control_entrypoint_mints_tokens_the_broker_accepts(tmp_path, monkeypatch):
    """The two halves are one keypair: the control plane signs with the
    private file, the broker verifies with the public file, and neither ever
    sees the other's half."""
    private_path, public_path = write_keypair(tmp_path)

    control_app = control_main.build(control_config(tmp_path, private_path))
    response = TestClient(control_app).post(
        "/v1/tokens",
        json={
            "agent_id": "triage-bot", "task_id": "4711", "purpose": "support-triage",
            "allowed_tools": ["read_document"], "data_classes": ["public"],
            "counterparties": ["customer:8812"],
        },
    )
    assert response.status_code == 200

    set_catalog_env(monkeypatch, tmp_path)
    _, components = broker_main.build(broker_config(tmp_path, public_path), client=stub_client())
    token = components.verifier.verify(response.json()["token"])
    assert token.agent_id == "triage-bot"
    assert token.allowed_tools == ("read_document",)


def test_control_entrypoint_refuses_a_missing_private_key(tmp_path):
    config = control_config(tmp_path, tmp_path / "absent.key")
    with pytest.raises(FileNotFoundError):
        control_main.build(config)


def test_control_entrypoint_refuses_a_public_key_where_the_private_one_belongs(tmp_path):
    """Handing the control plane the wrong half must fail at startup, not at
    the first mint."""
    _, public_path = write_keypair(tmp_path)
    config = control_config(tmp_path, public_path)
    with pytest.raises(ValueError):
        control_main.build(config)


def test_openssl_generated_keys_are_the_keys_the_code_loads(tmp_path, monkeypatch):
    """`warden-demo up` and tests/test_isolation.sh generate the keypair with
    openssl, outside every container. Nothing else in the suite exercises that
    exact format (PKCS#8 private, SubjectPublicKeyInfo public), so a format
    mismatch would only show up in the room."""
    if shutil.which("openssl") is None:  # pragma: no cover
        pytest.skip("openssl not installed")

    private_path = tmp_path / "agent.key"
    public_path = tmp_path / "agent.pub"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(private_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
        check=True, capture_output=True,
    )

    control_app = control_main.build(control_config(tmp_path, private_path))
    response = TestClient(control_app).post(
        "/v1/tokens",
        json={
            "agent_id": "triage-bot", "task_id": "4711", "purpose": "support-triage",
            "allowed_tools": ["read_document"], "data_classes": ["public"],
            "counterparties": ["customer:8812"],
        },
    )
    assert response.status_code == 200

    set_catalog_env(monkeypatch, tmp_path)
    _, components = broker_main.build(broker_config(tmp_path, public_path), client=stub_client())
    assert components.verifier.verify(response.json()["token"]).purpose == "support-triage"


# --- Topology, by inspection ------------------------------------------------
#
# Docker is not available here, so this is a read of the compose file rather
# than a live probe. It is still worth pinning: the entire property rests on
# broker-control never being attached to agent-net, and that is one word in
# one file. Deliberately parsed by hand rather than with PyYAML -- PyYAML is
# not in requirements.txt, and a topology check that silently skips in CI is
# worse than no check.


def _compose_service_block(name: str) -> str:
    """The configuration lines of one service, comments stripped.

    Comments are dropped deliberately: these assertions are about what Docker
    is told, and prose describing a neighbouring service would otherwise
    satisfy -- or falsify -- a substring check for the wrong reason.

    Task 22 split the single docker-compose.yml into compose.yml (opa,
    broker, broker-control) and demo/compose.demo.yml (everything else), so
    a service is looked up in whichever of the two actually declares it --
    the split is exactly what test_the_demo_compose_declares_no_product_service
    and test_the_product_compose_keeps_the_guarded_profile in test_seam.py
    pin, so a service name never legitimately appears in both.
    """
    for compose_path in (REPO_ROOT / "compose.yml", REPO_ROOT / "demo" / "compose.demo.yml"):
        lines = [
            line
            for line in compose_path.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        start = next((i for i, line in enumerate(lines) if line == f"  {name}:"), None)
        if start is None:
            continue
        end = next(
            (i for i in range(start + 1, len(lines)) if line_starts_a_service(lines[i])),
            len(lines),
        )
        return "\n".join(lines[start:end])
    raise AssertionError(f"service {name!r} not found in compose.yml or demo/compose.demo.yml")


def line_starts_a_service(line: str) -> bool:
    return line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":")


def test_the_minting_service_is_not_attached_to_the_agent_network():
    block = _compose_service_block("broker-control")
    assert "warden.broker.control_main" in block
    assert "backend-net" in block
    assert "agent-net" not in block


def test_the_broker_service_no_longer_publishes_the_control_port():
    """The broker is on agent-net, so nothing that mints may run in it."""
    block = _compose_service_block("broker")
    assert "8081" not in block
    assert "control" not in block


def test_the_inspection_scanner_can_actually_see_a_network_attachment():
    """Positive control: without this, the assertion above would pass just as
    happily against a scanner that reads the wrong block or an empty string."""
    assert "agent-net" in _compose_service_block("agent-runtime")
    assert "agent-net" in _compose_service_block("broker")


def test_the_broker_and_control_services_mount_their_toml_config():
    """Task 14 moved ports, paths, the OPA URL and the token issuer/TTL out of
    the source and into warden.toml / control.toml. A service that forgot to
    mount its file, or to point WARDEN_CONFIG / WARDEN_CONTROL_CONFIG at it,
    would boot against /config/warden.toml inside an image that never put
    anything there -- a startup crash the unit tests above cannot see."""
    broker_block = _compose_service_block("broker")
    assert "WARDEN_CONFIG: /config/warden.toml" in broker_block
    assert "./demo/scenario/warden.toml:/config/warden.toml:ro" in broker_block

    control_block = _compose_service_block("broker-control")
    assert "WARDEN_CONTROL_CONFIG: /config/control.toml" in control_block
    assert "./demo/scenario/control.toml:/config/control.toml:ro" in control_block


def test_warden_demo_up_rebuilds_before_starting_containers():
    """A stale image runs old code while the run looks current.

    Observed: an image predating the R7 `subjects` change emitted a target
    dict without that key, the policy denied it input.malformed (correctly),
    the task therefore never became tainted, and the PII POST to the
    allowlisted internal endpoint SUCCEEDED -- the demo's central claim,
    inverted, under a chain that reported itself intact.

    `docker compose ... up` is not the only invocation that can start a
    stale container: `docker compose ... run` does too, and `run` is what
    starts agent-runtime -- the service most likely to go stale, because it
    carries the scenario code Task 20 moved. Observed directly during that
    task's own Docker verification: a `run` line with no `--build` silently
    reused a pre-move image and crashed on an import the pre-move image
    never had -- the exact failure mode this test exists to catch, just on
    the invocation kind it did not yet check. Both `up` and `run` are
    checked here now, each against its own expected count, so neither kind
    can silently gain an unguarded line.

    Task 24 retired demo/scripts/demo.sh (this test used to scan its text)
    and moved the same orchestration into demo.cli.main._cmd_up. Re-pointed
    here at the real dispatch path rather than at a script's source: every
    `docker`/`openssl`/HTTP seam is mocked out and `_cmd_up` is actually
    RUN for both profiles, so the commands asserted on below are the ones
    the code really emits -- a call site that drops `--build` fails this by
    being exercised, not by a grep that a stray comment could fool.
    """
    import argparse
    from unittest.mock import patch

    from demo.cli import main as demo_main

    calls: list[tuple] = []
    with patch.object(demo_main, "_compose", lambda *a, **k: calls.append(a)), \
         patch.object(demo_main, "_wait_for_broker_control", lambda: None), \
         patch.object(demo_main, "_generate_keypair", lambda directory: None), \
         patch.object(demo_main, "seed_customers", lambda path, count: None), \
         patch.object(demo_main, "_mint_token", lambda: "minted-token"), \
         patch.object(demo_main, "_print_sinkhole_report", lambda: None), \
         patch.object(demo_main, "_replay", lambda task_id: 0):
        for profile in ("guarded", "unprotected"):
            demo_main._cmd_up(argparse.Namespace(profile=profile, live=False))

    ups = [call for call in calls if "up" in call]
    runs = [call for call in calls if "run" in call]
    assert len(ups) == 2, f"expected exactly one `docker compose ... up` per profile, found {len(ups)}: {ups}"
    assert len(runs) == 2, f"expected exactly one `docker compose ... run` per profile, found {len(runs)}: {runs}"
    for call in ups + runs:
        assert "--build" in call, f"docker compose invocation without --build: {call}"
