"""A config typo must not greet an operator with a Python traceback.

`warden serve`, `warden control` and `warden config check` all load config
before doing anything else, and none of them had a single try/except in that
path: a ConfigError (a malformed warden.toml, or a tools.toml binding key an
adapter does not recognise -- see broker/config/loader.py and
broker/config/catalog.py) or an OSError reading a config-named file (a
public_key / private_key path that is not there) reached the operator as
~20 lines of interpreter internals, on the enforcement point's own boot path.

Exit codes are unchanged: an uncaught exception already exited 1 (Python's
default for main() raising past sys.exit(main())), and every test below
still asserts 1. What changes is presentation -- a one-line `error: ...` on
stderr, no `Traceback` anywhere in stdout or stderr -- not behaviour: a
broker that cannot understand its own config must still refuse to start.

Two exception shapes are exercised per entry point on purpose: ConfigError
(a config file that parses to something invalid) and OSError (a config file
that names a *second* file -- a key, a data document -- which is not there).
They are raised from different call sites (the TOML loader vs.
identity.py's Path.read_bytes()), so a fix that catches only one leaves the
other's traceback intact; both must be covered.
"""

from __future__ import annotations

from pathlib import Path

from warden.cli.main import main as cli_main

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
POLICIES = REPO_ROOT / "warden" / "policies"


def _assert_clean_failure(capsys, exit_code: int) -> str:
    """Shared shape every test below checks: non-zero exit, no Traceback
    anywhere, something on stderr. Returns stderr for the caller's own
    content assertion."""
    captured = capsys.readouterr()
    assert exit_code != 0
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert captured.err.strip() != ""
    return captured.err


# --- warden serve ------------------------------------------------------------


def test_serve_reports_a_missing_config_file_cleanly(tmp_path, capsys):
    """ConfigError, raised by load_broker_config() -> _load_toml() before
    build() is ever called -- the warden.toml path itself is wrong."""
    missing = tmp_path / "warden.toml"  # never written
    exit_code = cli_main(["serve", "--config", str(missing)])
    stderr = _assert_clean_failure(capsys, exit_code)
    assert exit_code == 1
    assert "config not found" in stderr
    assert str(missing) in stderr


def test_serve_reports_a_missing_public_key_file_cleanly(tmp_path, capsys):
    """OSError, raised by Verifier.from_public_key_file()'s Path.read_bytes()
    inside build() -- warden.toml itself is well-formed, but the file it
    points [identity].public_key at is not there. This is the FileNotFoundError
    case the finding names ("a missing key file"), a different call site and
    a different exception type than the ConfigError test above -- catching
    only ConfigError would still crash this one."""
    missing_key = tmp_path / "agent.pub"  # never written
    config = tmp_path / "warden.toml"
    config.write_text(f"""
[broker]
listen       = "127.0.0.1:18080"
proxy_listen = "127.0.0.1:13128"

[identity]
public_key = "{missing_key}"

[policy]
opa_url       = "http://opa:8181"
decision_path = "warden/authz"
bundle_roots  = ["{tmp_path / 'unused-bundle'}"]

[audit]
path = "{tmp_path / 'audit.jsonl'}"

[tokens]
issuer = "warden-broker"

[catalog]
tools = "{tmp_path / 'unused-tools.toml'}"
""")
    exit_code = cli_main(["serve", "--config", str(config)])
    stderr = _assert_clean_failure(capsys, exit_code)
    assert exit_code == 1
    assert str(missing_key) in stderr


# --- warden control ------------------------------------------------------------


def test_control_reports_a_missing_config_file_cleanly(tmp_path, capsys):
    missing = tmp_path / "control.toml"  # never written
    exit_code = cli_main(["control", "--config", str(missing)])
    stderr = _assert_clean_failure(capsys, exit_code)
    assert exit_code == 1
    assert "config not found" in stderr
    assert str(missing) in stderr


def test_control_reports_a_missing_private_key_file_cleanly(tmp_path, capsys):
    """OSError from Signer.from_private_key_file()'s Path.read_bytes() inside
    control_main.build() -- control.toml itself is well-formed."""
    missing_key = tmp_path / "agent.key"  # never written
    config = tmp_path / "control.toml"
    config.write_text(f"""
[control]
listen = "127.0.0.1:18081"

[identity]
private_key = "{missing_key}"

[tokens]
issuer      = "warden-broker"
ttl_seconds = 300
""")
    exit_code = cli_main(["control", "--config", str(config)])
    stderr = _assert_clean_failure(capsys, exit_code)
    assert exit_code == 1
    assert str(missing_key) in stderr


# --- warden config check -----------------------------------------------------


BAD_BINDING_MANIFEST = """
[tools.query_customers]
kind = "sql"
[tools.query_customers.binding]
db              = "x.db"
table           = "customers"
columns         = ["id", "name"]
subject_prefixx = "cust:"
subject_column  = "id"
default_column  = "name"
[tools.query_customers.args]
subject = { type = "string", required = true }
"""


def test_config_check_reports_a_bad_binding_key_cleanly(tmp_path, capsys):
    """The exact reproduction from the review: a typo'd binding key
    (subject_prefixx for subject_prefix) raised ConfigError from
    check_catalog() -> load_catalog() -> _check_binding_keys(), uncaught."""
    catalog = tmp_path / "tools.toml"
    catalog.write_text(BAD_BINDING_MANIFEST)
    data = tmp_path / "data.json"
    data.write_text("{}")
    exit_code = cli_main(
        ["config", "check", "--catalog", str(catalog), "--data", str(data)]
    )
    stderr = _assert_clean_failure(capsys, exit_code)
    assert exit_code == 1
    assert "subject_prefixx" in stderr
    assert "not a recognised key" in stderr


def test_config_check_reports_a_missing_data_file_cleanly(tmp_path, capsys):
    """OSError: --catalog parses fine, --data names a file that is not
    there. json.loads(Path(data_path).read_text()) inside check_catalog()
    raises FileNotFoundError before ever calling check_catalog_findings()."""
    catalog = tmp_path / "tools.toml"
    catalog.write_text("""
[tools.read_document]
kind = "docstore"
[tools.read_document.binding]
base_url = "http://d"
[tools.read_document.args]
doc_id = { type = "string", required = true }
""")
    missing_data = tmp_path / "data.json"  # never written
    exit_code = cli_main(
        ["config", "check", "--catalog", str(catalog), "--data", str(missing_data)]
    )
    stderr = _assert_clean_failure(capsys, exit_code)
    assert exit_code == 1
    assert str(missing_data) in stderr
