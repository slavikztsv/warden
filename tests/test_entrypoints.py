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
"""

from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import broker.__main__ as broker_main
import broker.control_main as control_main
from broker.identity import Signer, Verifier
from mocks.seed_db import seed_customers

REPO_ROOT = Path(__file__).resolve().parent.parent


def write_keypair(directory: Path) -> tuple[Path, Path]:
    """Generates a keypair to two files, the way scripts/demo.sh does."""
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


def broker_env(tmp_path: Path, public_path: Path) -> dict[str, str]:
    seed_customers(tmp_path / "customers.db", count=5)
    return {
        "AGENT_PUBLIC_KEY_PATH": str(public_path),
        "OPA_URL": "http://opa:8181",
        "AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        "DOCSTORE_URL": "http://docstore.internal",
        "MAILER_URL": "http://mailer.internal",
        "DB_PATH": str(tmp_path / "customers.db"),
        "POLICY_PATH": str(REPO_ROOT / "policies"),
    }


def stub_client() -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x")))


# --- The broker process: verifies, never mints -----------------------------


def test_broker_wiring_builds_a_verifier_from_a_public_key_file(tmp_path):
    private_path, public_path = write_keypair(tmp_path)
    _, deps = broker_main.build(broker_env(tmp_path, public_path), client=stub_client())

    assert isinstance(deps["verifier"], Verifier)
    # It is the right key, not merely a Verifier-shaped object: a token minted
    # by the private half of the same pair must verify.
    token = Signer.from_private_key_file(private_path).mint(
        agent_id="triage-bot", task_id="4711", purpose="support-triage",
        allowed_tools=["read_document"], data_classes=["public"],
        counterparties=["customer:8812"],
    )
    assert deps["verifier"].verify(token).task_id == "4711"


def test_broker_verifier_rejects_a_token_from_any_other_key(tmp_path):
    """Negative control for the test above: the verifier is bound to that one
    public key, so a token minted anywhere else -- including by a Signer the
    broker might once have generated for itself -- is refused."""
    from broker.identity import TokenInvalid

    _, public_path = write_keypair(tmp_path)
    _, deps = broker_main.build(broker_env(tmp_path, public_path), client=stub_client())

    foreign = Signer.generate().mint(
        agent_id="triage-bot", task_id="4711", purpose="support-triage",
        allowed_tools=["read_document", "query_customers", "http_fetch", "send_email"],
        data_classes=["pii"], counterparties=["attacker@evil.example"],
    )
    with pytest.raises(TokenInvalid):
        deps["verifier"].verify(foreign)


def test_broker_process_holds_no_signing_key(tmp_path):
    """The enforcement point is the service the agent can reach, so it is the
    service most exposed to a subverted agent. It must hold no material that
    can sign a token: not a Signer, not an Ed25519 private key, anywhere in
    the objects it wires up."""
    _, public_path = write_keypair(tmp_path)
    app, deps = broker_main.build(broker_env(tmp_path, public_path), client=stub_client())

    def reachable_objects(root, seen=None, depth=0):
        if seen is None:
            seen = set()
        if depth > 4 or id(root) in seen:
            return
        seen.add(id(root))
        yield root
        values = root.values() if isinstance(root, dict) else []
        attrs = getattr(root, "__dict__", {}).values()
        for child in [*values, *attrs]:
            yield from reachable_objects(child, seen, depth + 1)

    for obj in reachable_objects({"app": app, "deps": deps}):
        assert not isinstance(obj, Signer), "the broker wired up a Signer"
        assert not isinstance(obj, Ed25519PrivateKey), "the broker holds a private key"


def test_broker_entrypoint_source_never_names_the_signer():
    """Structural, not behavioural: even an unexecuted branch that reaches for
    Signer in this module would reintroduce the escalation path, so assert the
    name does not appear in the module at all. Signer.generate() lived here."""
    source = (REPO_ROOT / "broker" / "__main__.py").read_text()
    tree = ast.parse(source)
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= {alias.name for alias in node.names}
    assert "Signer" not in names
    assert "create_control_app" not in names


def test_broker_app_exposes_no_minting_route(tmp_path):
    _, public_path = write_keypair(tmp_path)
    app, _ = broker_main.build(broker_env(tmp_path, public_path), client=stub_client())

    assert not any("token" in route.path for route in app.routes)
    assert TestClient(app).post("/v1/tokens", json={}).status_code == 404


def test_broker_refuses_to_start_without_the_public_key(tmp_path):
    """Fail closed at startup. A broker that came up with no verification key
    would have to either trust everything or reject everything, and finding
    out which at request time is not acceptable for an enforcement point."""
    env = broker_env(tmp_path, tmp_path / "absent.pub")
    with pytest.raises(FileNotFoundError):
        broker_main.build(env, client=stub_client())


def test_broker_refuses_a_public_key_file_that_is_not_ed25519(tmp_path):
    _, public_path = write_keypair(tmp_path)
    public_path.write_bytes(b"-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n")
    with pytest.raises(Exception):
        broker_main.build(broker_env(tmp_path, public_path), client=stub_client())


def test_broker_wiring_digests_every_policy_path_root(tmp_path):
    """POLICY_PATH may name more than one root, colon-separated -- this is the
    one production entry point the whole policy_bundle_digest signature
    change exists for. A bundle split across a rules root and a data root
    must be digested as one, so changing a file in the SECOND root must
    change the digest the broker wires up at startup. The previous
    single-directory digest would have silently ignored a second root:
    max_rows_per_task 50 -> 5,000,000 with every audit record still claiming
    the identical policy."""
    _, public_path = write_keypair(tmp_path)

    rules_root = tmp_path / "policy_rules"
    data_root = tmp_path / "policy_data"
    rules_root.mkdir()
    data_root.mkdir()
    (rules_root / "authz.rego").write_text("package warden.authz\n")
    (data_root / "data.json").write_text('{"limits": {"max_rows_per_task": 50}}\n')

    env = broker_env(tmp_path, public_path)
    env["POLICY_PATH"] = f"{rules_root}:{data_root}"

    _, deps_before = broker_main.build(env, client=stub_client())

    (data_root / "data.json").write_text('{"limits": {"max_rows_per_task": 5000000}}\n')

    _, deps_after = broker_main.build(env, client=stub_client())

    assert deps_before["policy_digest"] != deps_after["policy_digest"]


# --- The control process: the only minter ----------------------------------


def test_control_entrypoint_mints_tokens_the_broker_accepts(tmp_path):
    """The two halves are one keypair: the control plane signs with the
    private file, the broker verifies with the public file, and neither ever
    sees the other's half."""
    private_path, public_path = write_keypair(tmp_path)

    control_app = control_main.build({"AGENT_PRIVATE_KEY_PATH": str(private_path)})
    response = TestClient(control_app).post(
        "/v1/tokens",
        json={
            "agent_id": "triage-bot", "task_id": "4711", "purpose": "support-triage",
            "allowed_tools": ["read_document"], "data_classes": ["public"],
            "counterparties": ["customer:8812"],
        },
    )
    assert response.status_code == 200

    _, deps = broker_main.build(broker_env(tmp_path, public_path), client=stub_client())
    token = deps["verifier"].verify(response.json()["token"])
    assert token.agent_id == "triage-bot"
    assert token.allowed_tools == ("read_document",)


def test_control_entrypoint_refuses_a_missing_private_key(tmp_path):
    with pytest.raises(FileNotFoundError):
        control_main.build({"AGENT_PRIVATE_KEY_PATH": str(tmp_path / "absent.key")})


def test_control_entrypoint_refuses_a_public_key_where_the_private_one_belongs(tmp_path):
    """Handing the control plane the wrong half must fail at startup, not at
    the first mint."""
    _, public_path = write_keypair(tmp_path)
    with pytest.raises(ValueError):
        control_main.build({"AGENT_PRIVATE_KEY_PATH": str(public_path)})


def test_openssl_generated_keys_are_the_keys_the_code_loads(tmp_path):
    """scripts/demo.sh and tests/test_isolation.sh generate the keypair with
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

    control_app = control_main.build({"AGENT_PRIVATE_KEY_PATH": str(private_path)})
    response = TestClient(control_app).post(
        "/v1/tokens",
        json={
            "agent_id": "triage-bot", "task_id": "4711", "purpose": "support-triage",
            "allowed_tools": ["read_document"], "data_classes": ["public"],
            "counterparties": ["customer:8812"],
        },
    )
    assert response.status_code == 200

    _, deps = broker_main.build(broker_env(tmp_path, public_path), client=stub_client())
    assert deps["verifier"].verify(response.json()["token"]).purpose == "support-triage"


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
    """
    lines = [
        line
        for line in (REPO_ROOT / "docker-compose.yml").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    start = next(i for i, line in enumerate(lines) if line == f"  {name}:")
    end = next(
        (i for i in range(start + 1, len(lines)) if line_starts_a_service(lines[i])),
        len(lines),
    )
    return "\n".join(lines[start:end])


def line_starts_a_service(line: str) -> bool:
    return line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":")


def test_the_minting_service_is_not_attached_to_the_agent_network():
    block = _compose_service_block("broker-control")
    assert "broker.control_main" in block
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


def test_demo_script_rebuilds_before_starting_containers():
    """A stale image runs old code while the run looks current.

    Observed: an image predating the R7 `subjects` change emitted a target
    dict without that key, the policy denied it input.malformed (correctly),
    the task therefore never became tainted, and the PII POST to the
    allowlisted internal endpoint SUCCEEDED -- the demo's central claim,
    inverted, under a chain that reported itself intact.
    """
    script = (REPO_ROOT / "scripts" / "demo.sh").read_text()
    ups = [line for line in script.splitlines() if "docker compose" in line and " up " in line]
    assert ups, "no `docker compose up` found in demo.sh"
    for line in ups:
        assert "--build" in line, f"up without --build: {line.strip()}"
