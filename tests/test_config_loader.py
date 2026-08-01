"""Wiring comes from a file, and a file that is wrong stops the process.

Every failure here is a startup failure by design. A broker that boots with a
half-understood config is a broker whose audit records claim a policy it is
not enforcing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from broker.config.loader import BrokerConfig, ConfigError, interpolate, load_broker_config

COMPLETE = """
[broker]
listen       = "0.0.0.0:8080"
proxy_listen = "0.0.0.0:3128"

[identity]
public_key = "/data/agent.pub"

[policy]
opa_url       = "http://opa:8181"
decision_path = "warden/authz"
bundle_roots  = ["/policies"]

[audit]
path = "/data/audit.jsonl"

[tokens]
issuer      = "warden-broker"
ttl_seconds = 300

[catalog]
tools = "/config/tools.toml"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "warden.toml"
    path.write_text(text)
    return path


def test_loads_every_field(tmp_path):
    config = load_broker_config(write(tmp_path, COMPLETE), env={})
    assert isinstance(config, BrokerConfig)
    assert config.listen == ("0.0.0.0", 8080)
    assert config.proxy_listen == ("0.0.0.0", 3128)
    assert config.public_key == Path("/data/agent.pub")
    assert config.opa_url == "http://opa:8181"
    assert config.decision_path == "warden/authz"
    assert config.bundle_roots == (Path("/policies"),)
    assert config.audit_path == Path("/data/audit.jsonl")
    assert config.issuer == "warden-broker"
    assert config.ttl_seconds == 300
    assert config.catalog_path == Path("/config/tools.toml")


def test_is_frozen(tmp_path):
    config = load_broker_config(write(tmp_path, COMPLETE), env={})
    with pytest.raises(Exception):
        config.opa_url = "http://elsewhere"


def test_interpolates_from_the_environment(tmp_path):
    text = COMPLETE.replace('"http://opa:8181"', '"${OPA_URL}"')
    config = load_broker_config(write(tmp_path, text), env={"OPA_URL": "http://x:1"})
    assert config.opa_url == "http://x:1"


def test_an_unset_variable_is_a_startup_failure(tmp_path):
    """Fail closed. Substituting an empty string would point the PDP at
    nothing and every decision would become pdp.unavailable at runtime,
    discovered in production rather than at boot."""
    text = COMPLETE.replace('"http://opa:8181"', '"${OPA_URL}"')
    with pytest.raises(ConfigError, match="OPA_URL"):
        load_broker_config(write(tmp_path, text), env={})


def test_interpolate_handles_several_and_leaves_other_text_alone():
    assert interpolate("a${X}b${Y}c", {"X": "1", "Y": "2"}) == "a1b2c"
    assert interpolate("no vars", {}) == "no vars"


def test_a_missing_section_names_itself(tmp_path):
    text = COMPLETE.replace("[audit]\npath = \"/data/audit.jsonl\"\n", "")
    with pytest.raises(ConfigError, match="audit"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_missing_key_names_itself(tmp_path):
    text = COMPLETE.replace('opa_url       = "http://opa:8181"\n', "")
    with pytest.raises(ConfigError, match="policy.opa_url"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_wrong_type_is_rejected(tmp_path):
    text = COMPLETE.replace("ttl_seconds = 300", 'ttl_seconds = "300"')
    with pytest.raises(ConfigError, match="tokens.ttl_seconds"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_malformed_listen_address_is_rejected(tmp_path):
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "0.0.0.0"')
    with pytest.raises(ConfigError, match="broker.listen"):
        load_broker_config(write(tmp_path, text), env={})


def test_empty_bundle_roots_is_rejected(tmp_path):
    """No roots means the digest covers nothing, so every audit record would
    stamp the same value whatever the policy said."""
    text = COMPLETE.replace('bundle_roots  = ["/policies"]', "bundle_roots  = []")
    with pytest.raises(ConfigError, match="policy.bundle_roots"):
        load_broker_config(write(tmp_path, text), env={})


def test_a_missing_file_names_the_path(tmp_path):
    with pytest.raises(ConfigError, match="absent.toml"):
        load_broker_config(tmp_path / "absent.toml", env={})


def test_invalid_toml_names_the_file(tmp_path):
    path = write(tmp_path, "[broker\n")
    with pytest.raises(ConfigError, match="warden.toml"):
        load_broker_config(path, env={})


# Finding 1 (Important) — empty strings must be rejected, not silently accepted
def test_an_empty_string_literal_is_rejected(tmp_path):
    """An empty string in the config is as bad as an empty environment variable."""
    text = COMPLETE.replace('"http://opa:8181"', '""')
    with pytest.raises(ConfigError, match="policy.opa_url.*must not be empty"):
        load_broker_config(write(tmp_path, text), env={})


def test_an_empty_interpolated_string_is_rejected(tmp_path):
    """Setting OPA_URL= (empty) in the environment should also fail."""
    text = COMPLETE.replace('"http://opa:8181"', '"${OPA_URL}"')
    with pytest.raises(ConfigError, match="policy.opa_url.*must not be empty"):
        load_broker_config(write(tmp_path, text), env={"OPA_URL": ""})


def test_empty_bundle_root_entry_is_rejected(tmp_path):
    """An empty path in bundle_roots must be rejected."""
    text = COMPLETE.replace('bundle_roots  = ["/policies"]', 'bundle_roots  = [""]')
    with pytest.raises(ConfigError, match="policy.bundle_roots.*must not be empty"):
        load_broker_config(write(tmp_path, text), env={})


# Finding 2 (Important) — IPv6 and port range validation
def test_ipv6_without_brackets_is_rejected(tmp_path):
    """A bare IPv6 address like ::1 splits incorrectly and must be rejected."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "::1"')
    with pytest.raises(ConfigError, match="broker.listen.*host contains"):
        load_broker_config(write(tmp_path, text), env={})


def test_ipv6_with_brackets_is_accepted(tmp_path):
    """The standard IPv6 literal form [::1]:8080 should be accepted."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "[::1]:8080"')
    config = load_broker_config(write(tmp_path, text), env={})
    assert config.listen == ("::1", 8080)


def test_port_zero_is_rejected(tmp_path):
    """Port 0 is not usable for binding."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "0.0.0.0:0"')
    with pytest.raises(ConfigError, match="broker.listen.*port must be 1-65535"):
        load_broker_config(write(tmp_path, text), env={})


def test_port_out_of_range_is_rejected(tmp_path):
    """Ports above 65535 are invalid."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "0.0.0.0:70000"')
    with pytest.raises(ConfigError, match="broker.listen.*port must be 1-65535"):
        load_broker_config(write(tmp_path, text), env={})


# Finding 3 (Minor) — the bool guard needs a test
def test_a_boolean_ttl_is_rejected(tmp_path):
    """bool is an int subclass; ttl_seconds = true should error, not become 1."""
    text = COMPLETE.replace("ttl_seconds = 300", "ttl_seconds = true")
    with pytest.raises(ConfigError, match="tokens.ttl_seconds"):
        load_broker_config(write(tmp_path, text), env={})
