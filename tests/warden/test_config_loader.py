"""Wiring comes from a file, and a file that is wrong stops the process.

Every failure here is a startup failure by design. A broker that boots with a
half-understood config is a broker whose audit records claim a policy it is
not enforcing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from warden.broker.config.loader import (
    BrokerConfig,
    ConfigError,
    ControlConfig,
    interpolate,
    load_broker_config,
    load_control_config,
)

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
issuer = "warden-broker"

[catalog]
tools = "/config/tools.toml"
"""


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "warden.toml"
    path.write_text(text)
    return path


def write_complete_config(tmp_path: Path) -> Path:
    return write(tmp_path, COMPLETE)


def test_loads_every_field(tmp_path):
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert isinstance(config, BrokerConfig)
    assert config.listen == ("0.0.0.0", 8080)
    assert config.proxy_listen == ("0.0.0.0", 3128)
    assert config.public_key == Path("/data/agent.pub")
    assert config.opa_url == "http://opa:8181"
    assert config.decision_path == "warden/authz"
    assert config.bundle_roots == (Path("/policies"),)
    assert config.audit_path == Path("/data/audit.jsonl")
    assert config.audit_durability == "fsync"
    assert config.issuer == "warden-broker"
    assert config.catalog_path == Path("/config/tools.toml")
    # ttl_seconds is deliberately NOT a BrokerConfig field: the broker
    # verifies a token's issuer but never mints, so a TTL here would be
    # parsed and never consumed. It lives on ControlConfig only (see below).
    assert not hasattr(config, "ttl_seconds")


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
    with pytest.raises(ConfigError, match=re.escape("OPA_URL")):
        load_broker_config(write(tmp_path, text), env={})


def test_interpolate_handles_several_and_leaves_other_text_alone():
    assert interpolate("a${X}b${Y}c", {"X": "1", "Y": "2"}) == "a1b2c"
    assert interpolate("no vars", {}) == "no vars"


def test_a_missing_section_names_itself(tmp_path):
    text = COMPLETE.replace("[audit]\npath = \"/data/audit.jsonl\"\n", "")
    with pytest.raises(ConfigError, match=re.escape("audit")):
        load_broker_config(write(tmp_path, text), env={})


def test_a_missing_key_names_itself(tmp_path):
    text = COMPLETE.replace('opa_url       = "http://opa:8181"\n', "")
    with pytest.raises(ConfigError, match=re.escape("policy.opa_url")):
        load_broker_config(write(tmp_path, text), env={})


def test_a_wrong_type_is_rejected(tmp_path):
    text = COMPLETE.replace('issuer = "warden-broker"', "issuer = 300")
    with pytest.raises(ConfigError, match=re.escape("tokens.issuer")):
        load_broker_config(write(tmp_path, text), env={})


def test_a_malformed_listen_address_is_rejected(tmp_path):
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "0.0.0.0"')
    with pytest.raises(ConfigError, match=re.escape("broker.listen")):
        load_broker_config(write(tmp_path, text), env={})


def test_empty_bundle_roots_is_rejected(tmp_path):
    """No roots means the digest covers nothing, so every audit record would
    stamp the same value whatever the policy said."""
    text = COMPLETE.replace('bundle_roots  = ["/policies"]', "bundle_roots  = []")
    with pytest.raises(ConfigError, match=re.escape("policy.bundle_roots")):
        load_broker_config(write(tmp_path, text), env={})


def test_a_missing_file_names_the_path(tmp_path):
    with pytest.raises(ConfigError, match=re.escape("absent.toml")):
        load_broker_config(tmp_path / "absent.toml", env={})


def test_invalid_toml_names_the_file(tmp_path):
    path = write(tmp_path, "[broker\n")
    with pytest.raises(ConfigError, match=re.escape("warden.toml")):
        load_broker_config(path, env={})


# Finding 1 (Important) — empty strings must be rejected, not silently accepted
def test_an_empty_string_literal_is_rejected(tmp_path):
    """An empty string in the config is as bad as an empty environment variable."""
    text = COMPLETE.replace('"http://opa:8181"', '""')
    with pytest.raises(ConfigError, match=r"policy\.opa_url.*must not be empty"):
        load_broker_config(write(tmp_path, text), env={})


def test_an_empty_interpolated_string_is_rejected(tmp_path):
    """Setting OPA_URL= (empty) in the environment should also fail."""
    text = COMPLETE.replace('"http://opa:8181"', '"${OPA_URL}"')
    with pytest.raises(ConfigError, match=r"policy\.opa_url.*must not be empty"):
        load_broker_config(write(tmp_path, text), env={"OPA_URL": ""})


def test_empty_bundle_root_entry_is_rejected(tmp_path):
    """An empty path in bundle_roots must be rejected."""
    text = COMPLETE.replace('bundle_roots  = ["/policies"]', 'bundle_roots  = [""]')
    with pytest.raises(ConfigError, match=r"policy\.bundle_roots.*must not be empty"):
        load_broker_config(write(tmp_path, text), env={})


# Finding 2 (Important) — IPv6 and port range validation
def test_ipv6_without_brackets_is_rejected(tmp_path):
    """A bare IPv6 address like ::1 splits incorrectly and must be rejected."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "::1"')
    with pytest.raises(ConfigError, match=r"broker\.listen.*host contains"):
        load_broker_config(write(tmp_path, text), env={})


def test_ipv6_with_brackets_is_accepted(tmp_path):
    """The standard IPv6 literal form [::1]:8080 should be accepted."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "[::1]:8080"')
    config = load_broker_config(write(tmp_path, text), env={})
    assert config.listen == ("::1", 8080)


def test_port_zero_is_rejected(tmp_path):
    """Port 0 is not usable for binding."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "0.0.0.0:0"')
    with pytest.raises(ConfigError, match=r"broker\.listen.*port must be 1-65535"):
        load_broker_config(write(tmp_path, text), env={})


def test_port_out_of_range_is_rejected(tmp_path):
    """Ports above 65535 are invalid."""
    text = COMPLETE.replace('listen       = "0.0.0.0:8080"', 'listen       = "0.0.0.0:70000"')
    with pytest.raises(ConfigError, match=r"broker\.listen.*port must be 1-65535"):
        load_broker_config(write(tmp_path, text), env={})


# --- ControlConfig: load_broker_config's symmetric sibling ------------------
#
# Task 14 review finding: load_broker_config had 20 tests; load_control_config
# had none of its own -- it was only exercised along the happy path via
# tests/warden/test_key_split.py, where the one "file absent" case actually failed
# inside Signer.from_private_key_file, not inside the loader. These mirror
# the broker-config tests above directly against load_control_config.
#
# IPv6-literal and port-range handling are deliberately NOT re-tested here:
# they exercise the same shared _address() helper the broker tests above
# already cover exhaustively, and control.toml's [control].listen goes
# through that identical function -- re-asserting every edge a second time
# would test the shared plumbing, not anything specific to ControlConfig.

CONTROL_COMPLETE = """
[control]
listen = "0.0.0.0:8081"

[identity]
private_key = "/data/agent.key"

[audit]
path = "/data/audit.jsonl"

[tokens]
issuer      = "warden-broker"
ttl_seconds = 300
"""


def write_control(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "control.toml"
    path.write_text(text)
    return path


def test_control_loads_every_field(tmp_path):
    config = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    assert isinstance(config, ControlConfig)
    assert config.listen == ("0.0.0.0", 8081)
    assert config.private_key == Path("/data/agent.key")
    assert config.audit_path == Path("/data/audit.jsonl")
    assert config.audit_durability == "fsync"
    assert config.issuer == "warden-broker"
    assert config.ttl_seconds == 300


def test_control_config_is_frozen(tmp_path):
    config = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    with pytest.raises(Exception):
        config.ttl_seconds = 3600


def test_control_interpolates_from_the_environment(tmp_path):
    text = CONTROL_COMPLETE.replace('"/data/agent.key"', '"${PRIVATE_KEY_PATH}"')
    config = load_control_config(
        write_control(tmp_path, text), env={"PRIVATE_KEY_PATH": "/other/agent.key"}
    )
    assert config.private_key == Path("/other/agent.key")


def test_control_an_unset_variable_is_a_startup_failure(tmp_path):
    text = CONTROL_COMPLETE.replace('"/data/agent.key"', '"${PRIVATE_KEY_PATH}"')
    with pytest.raises(ConfigError, match=re.escape("PRIVATE_KEY_PATH")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_missing_control_section_names_itself(tmp_path):
    text = CONTROL_COMPLETE.replace('[control]\nlisten = "0.0.0.0:8081"\n', "")
    with pytest.raises(ConfigError, match=re.escape("control")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_missing_identity_section_names_itself(tmp_path):
    text = CONTROL_COMPLETE.replace('[identity]\nprivate_key = "/data/agent.key"\n', "")
    with pytest.raises(ConfigError, match=re.escape("identity")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_missing_tokens_section_names_itself(tmp_path):
    """The gap this whole review finding is about: [tokens] on the control
    side is not decoration, it is where ttl_seconds actually lives now, so a
    control.toml missing it must refuse to start rather than mint under
    DEFAULT_TTL_SECONDS silently."""
    text = CONTROL_COMPLETE.replace('[tokens]\nissuer      = "warden-broker"\nttl_seconds = 300\n', "")
    with pytest.raises(ConfigError, match=re.escape("tokens")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_missing_audit_section_names_the_section(tmp_path):
    """B7: the control plane writes a mint record, so it needs a log to write
    it into, and it must not start without one.

    The assertion is the SECTION message, not merely that "audit" appears
    somewhere in the error, and that precision was earned by mutation. Swapping
    `_section` for `_optional_section` here leaves the boot failure intact --
    `_string` then raises "audit.path must be a string" against the empty dict,
    because `ControlConfig.audit_path` has no default to fall back to -- so a
    `match="audit"` version of this test passed against the exact change it
    names. What `_section` buys is the DIAGNOSIS: "missing or malformed section
    [audit]" sends an operator to the section they forgot, where the other
    message sends them to a key inside a table that is not there.

    The variant that would genuinely lose the property is
    `audit_path: Path | None = None` -- a control plane that starts and mints
    without recording. Nothing here is one line away from that, and this test
    is why.
    """
    text = CONTROL_COMPLETE.replace('[audit]\npath = "/data/audit.jsonl"\n', "")
    with pytest.raises(ConfigError, match=re.escape("missing or malformed section [audit]")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_missing_audit_path_names_itself(tmp_path):
    text = CONTROL_COMPLETE.replace('path = "/data/audit.jsonl"\n', "")
    with pytest.raises(ConfigError, match=re.escape("audit.path")):
        load_control_config(write_control(tmp_path, text), env={})


@pytest.mark.parametrize("ttl", ["0", "-1", "-300"])
def test_control_a_non_positive_ttl_refuses_to_load(tmp_path, ttl):
    """A token minted with a non-positive TTL is expired before it is issued.

    Always a broken deployment; what makes it a BOOT failure now is that B7's
    control plane verifies what it just signed in order to record the grant,
    so a zero TTL becomes an intermittent 500 on the mint route -- measured,
    4 mints in 200,000 raised TokenInvalid("token expired") because a second
    ticked over between signing and verifying. Refusing at load removes the
    failure rather than rendering it.
    """
    text = CONTROL_COMPLETE.replace("ttl_seconds = 300", f"ttl_seconds = {ttl}")
    with pytest.raises(ConfigError, match=r"tokens\.ttl_seconds must be positive"):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_missing_key_names_itself(tmp_path):
    text = CONTROL_COMPLETE.replace('private_key = "/data/agent.key"\n', "")
    with pytest.raises(ConfigError, match=re.escape("identity.private_key")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_malformed_listen_address_is_rejected(tmp_path):
    text = CONTROL_COMPLETE.replace('listen = "0.0.0.0:8081"', 'listen = "0.0.0.0"')
    with pytest.raises(ConfigError, match=re.escape("control.listen")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_missing_file_names_the_path(tmp_path):
    with pytest.raises(ConfigError, match=re.escape("absent.toml")):
        load_control_config(tmp_path / "absent.toml", env={})


def test_control_invalid_toml_names_the_file(tmp_path):
    path = write_control(tmp_path, "[control\n")
    with pytest.raises(ConfigError, match=re.escape("control.toml")):
        load_control_config(path, env={})


def test_control_an_empty_value_is_rejected(tmp_path):
    text = CONTROL_COMPLETE.replace('"/data/agent.key"', '""')
    with pytest.raises(ConfigError, match=r"identity\.private_key.*must not be empty"):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_wrong_type_ttl_is_rejected(tmp_path):
    """The scenario Task 14's review moved off BrokerConfig and onto
    ControlConfig: ttl_seconds is control-plane-only, so its type guard
    belongs -- and is tested -- here now."""
    text = CONTROL_COMPLETE.replace("ttl_seconds = 300", 'ttl_seconds = "300"')
    with pytest.raises(ConfigError, match=re.escape("tokens.ttl_seconds")):
        load_control_config(write_control(tmp_path, text), env={})


def test_control_a_boolean_ttl_is_rejected(tmp_path):
    """bool is an int subclass; ttl_seconds = true should error, not become 1."""
    text = CONTROL_COMPLETE.replace("ttl_seconds = 300", "ttl_seconds = true")
    with pytest.raises(ConfigError, match=re.escape("tokens.ttl_seconds")):
        load_control_config(write_control(tmp_path, text), env={})


# --- [mcp]: optional, off by default -----------------------------------------
#
# Every existing warden.toml has no [mcp] table. _section() raises on a
# missing section -- right for the six the broker cannot run without, wrong
# for a surface that must stay off unless a deployment explicitly asks for
# it. These confirm absence is structural (not a comment) and that a present
# [mcp] is parsed and validated like everything else here.


def test_mcp_is_absent_and_therefore_disabled(tmp_path):
    """Every existing warden.toml has no [mcp]. Absent must mean off, and it
    must be structural rather than a comment: _section() raises on a missing
    section, so reading [mcp] through it would stop every one of these
    configs from loading at all."""
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.mcp.enabled is False
    assert config.mcp.path == "/mcp"


def test_mcp_is_read_when_present(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(
        path.read_text()
        + '\n[mcp]\nenabled = true\npath = "/tools/mcp"\nhost = "broker.internal"\n'
    )
    config = load_broker_config(path, env={})
    assert config.mcp.enabled is True
    assert config.mcp.path == "/tools/mcp"
    assert config.mcp.host == "broker.internal"


def test_a_non_boolean_enabled_is_refused(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(path.read_text() + '\n[mcp]\nenabled = "yes"\n')
    with pytest.raises(ConfigError, match=re.escape("mcp.enabled")):
        load_broker_config(path, env={})


def test_a_malformed_mcp_section_names_itself(tmp_path):
    """mcp = "not a table" must precede any [table] header: TOML scopes a
    bare key=value to whichever table is currently open, so appending it
    after write_complete_config's trailing [catalog] would make it
    catalog.mcp rather than a top-level (and malformed) mcp key."""
    path = write_complete_config(tmp_path)
    path.write_text('mcp = "not a table"\n\n' + path.read_text())
    with pytest.raises(ConfigError, match=r"\[mcp\]"):
        load_broker_config(path, env={})


# --- [task_state]: optional, with defaults -----------------------------------
#
# Optional for the same structural reason [mcp] is: every warden.toml written
# before P2·A has no such table, and _section() would stop all of them from
# loading. Unlike [mcp] the defaults here are live rather than off -- there is
# no "disabled" state for task state, only a choice of two clocks.


def test_task_state_defaults_when_the_section_is_absent(tmp_path):
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.task_state.max_in_flight_seconds == 60
    assert config.task_state.ttl_grace_seconds == 3600


def test_task_state_is_read_when_present(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(
        path.read_text()
        + "\n[task_state]\nmax_in_flight_seconds = 90\nttl_grace_seconds = 120\n"
    )
    config = load_broker_config(path, env={})
    assert config.task_state.max_in_flight_seconds == 90
    assert config.task_state.ttl_grace_seconds == 120


def test_one_task_state_key_may_be_set_without_the_other(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(path.read_text() + "\n[task_state]\nttl_grace_seconds = 7200\n")
    config = load_broker_config(path, env={})
    assert config.task_state.max_in_flight_seconds == 60
    assert config.task_state.ttl_grace_seconds == 7200


def test_a_non_integer_task_state_value_is_refused(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(path.read_text() + '\n[task_state]\nmax_in_flight_seconds = "soon"\n')
    with pytest.raises(ConfigError, match=re.escape("task_state.max_in_flight_seconds")):
        load_broker_config(path, env={})


def test_a_non_positive_in_flight_deadline_is_refused(tmp_path):
    """Zero or less means every reservation is already expired when it is
    taken, so a charge would be collected by the same call that made it and
    the budget would never hold anything. Refuse at boot rather than serve a
    broker whose row budget silently does nothing."""
    path = write_complete_config(tmp_path)
    path.write_text(path.read_text() + "\n[task_state]\nmax_in_flight_seconds = 0\n")
    with pytest.raises(ConfigError, match=re.escape("task_state.max_in_flight_seconds")):
        load_broker_config(path, env={})


def test_a_negative_grace_is_refused(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text(path.read_text() + "\n[task_state]\nttl_grace_seconds = -1\n")
    with pytest.raises(ConfigError, match=re.escape("task_state.ttl_grace_seconds")):
        load_broker_config(path, env={})


def test_a_malformed_task_state_section_names_itself(tmp_path):
    path = write_complete_config(tmp_path)
    path.write_text('task_state = "not a table"\n\n' + path.read_text())
    with pytest.raises(ConfigError, match=r"\[task_state\]"):
        load_broker_config(path, env={})


def _with_broker_key(tmp_path: Path, line: str) -> Path:
    """COMPLETE's [broker] table comes first, so a key appended to the
    document would land under [catalog]. Inject under the header instead."""
    return write(tmp_path, COMPLETE.replace("[broker]\n", f"[broker]\n{line}\n", 1))


def test_worker_threads_defaults_when_absent(tmp_path):
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.worker_threads == 16


def test_worker_threads_is_read_when_present(tmp_path):
    path = _with_broker_key(tmp_path, "worker_threads = 4")
    assert load_broker_config(path, env={}).worker_threads == 4


def test_a_zero_worker_pool_is_refused(tmp_path):
    """A zero-thread pool accepts work and runs none of it, so every request
    would hang forever with the broker still reporting healthy. Same argument
    _positive already makes for max_in_flight_seconds: a config that silently
    disables the thing it configures is a boot failure, not a default."""
    path = _with_broker_key(tmp_path, "worker_threads = 0")
    with pytest.raises(ConfigError, match=re.escape("broker.worker_threads")):
        load_broker_config(path, env={})


def test_a_non_integer_worker_pool_is_refused(tmp_path):
    path = _with_broker_key(tmp_path, 'worker_threads = "lots"')
    with pytest.raises(ConfigError, match=re.escape("broker.worker_threads")):
        load_broker_config(path, env={})


def _with_task_state(tmp_path: Path, body: str) -> Path:
    return write(tmp_path, COMPLETE + f"\n[task_state]\n{body}\n")


def test_the_task_state_backend_defaults_to_memory(tmp_path):
    """Every config written before the shared store existed has no backend
    key, and all of them must keep loading -- and keep their own budget."""
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.task_state.backend == "memory"


def test_the_redis_backend_is_read_with_its_url(tmp_path):
    path = _with_task_state(tmp_path, 'backend = "redis"\nurl = "${REDIS_URL}"')
    config = load_broker_config(path, env={"REDIS_URL": "redis://cache:6379/0"})
    assert config.task_state.backend == "redis"
    assert config.task_state.url == "redis://cache:6379/0"


def test_an_unknown_backend_is_refused(tmp_path):
    path = _with_task_state(tmp_path, 'backend = "memcached"')
    with pytest.raises(ConfigError, match=re.escape("task_state.backend")):
        load_broker_config(path, env={})


def test_the_redis_backend_without_a_url_is_refused(tmp_path):
    """Not defaulted to localhost. A deployment that meant to SHARE a store
    would silently keep its own, which is the exact failure the shared store
    exists to remove."""
    path = _with_task_state(tmp_path, 'backend = "redis"')
    with pytest.raises(ConfigError, match=re.escape("task_state.url")):
        load_broker_config(path, env={})


def test_an_unset_redis_url_variable_fails_at_boot(tmp_path):
    path = _with_task_state(tmp_path, 'backend = "redis"\nurl = "${REDIS_URL}"')
    with pytest.raises(ConfigError, match="REDIS_URL"):
        load_broker_config(path, env={})


def test_a_socket_timeout_at_or_above_the_reservation_deadline_is_refused(tmp_path):
    """A store call that can outlive the reservation it is taking is a
    contradiction: the deadline would collect a live call's budget and hand it
    to a concurrent caller."""
    path = _with_task_state(
        tmp_path, "max_in_flight_seconds = 5\nsocket_timeout_seconds = 5"
    )
    with pytest.raises(ConfigError, match=re.escape("socket_timeout_seconds")):
        load_broker_config(path, env={})


# --- B2: [audit].durability, in BOTH loaders --------------------------------
#
# Designed in docs/superpowers/specs/2026-08-06-p2b2-audit-durability-design.md.
# Grouped rather than split between the broker and control sections above,
# because the point of decision 2 is the RELATIONSHIP between the two: the key
# is in both, and unlike [audit].path and [tokens].issuer the two values need
# not agree.

_AUDIT_SECTION = '[audit]\npath = "/data/audit.jsonl"'


def test_audit_durability_defaults_to_the_safe_level(tmp_path):
    """ROADMAP B2: "the default being the safe one". A config written before
    this key existed gets the STRONGER behaviour, never the weaker."""
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.audit_durability == "fsync"


def test_an_unrecognised_broker_durability_is_a_config_error(tmp_path):
    text = COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + '\ndurability = "fsyncc"')
    with pytest.raises(
        ConfigError,
        match=re.escape(
            "audit.durability must be one of ('fsync', 'flush'), got 'fsyncc'"
        ),
    ):
        load_broker_config(write(tmp_path, text), env={})


def test_the_control_plane_defaults_to_the_safe_level(tmp_path):
    config = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    assert config.audit_durability == "fsync"


def test_an_unrecognised_control_durability_is_a_config_error(tmp_path):
    """A non-string fails on the same check: the membership test type-checks
    for free, so there is no separate _string call to get wrong."""
    text = CONTROL_COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\ndurability = 3")
    with pytest.raises(
        ConfigError,
        match=re.escape("audit.durability must be one of ('fsync', 'flush'), got 3"),
    ):
        load_control_config(write_control(tmp_path, text), env={})


def test_the_two_writers_may_choose_different_durability(tmp_path):
    """Unlike [audit].path and [tokens].issuer -- which MUST agree, and whose
    divergence is a silent bug and a loud one respectively -- a broker at
    "flush" and a control plane at "fsync" is a coherent tiering: the grant
    must survive power loss, the high-volume decisions accept the risk.

    So there is deliberately NO check that the two agree, and this is the test
    that pins the absence. It is the one test here that would fail if someone
    "helpfully" added one.
    """
    broker = load_broker_config(
        write(tmp_path, COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + '\ndurability = "flush"')),
        env={},
    )
    control = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    assert broker.audit_durability == "flush"
    assert control.audit_durability == "fsync"
    # Same file, different durability. That is the point.
    assert broker.audit_path == control.audit_path


# --- B3: [audit].segment_bytes, in BOTH loaders -----------------------------
#
# Designed in docs/superpowers/specs/2026-08-06-p2b3-audit-segment-rotation-design.md.
# Grouped for the same reason the B2 block above is: the point is the
# relationship between the two values, not either one alone.


def test_audit_segment_bytes_defaults_to_64_mib(tmp_path):
    """Every config written before this key existed keeps loading, and gets what
    the product ships rather than what it replaced."""
    config = load_broker_config(write_complete_config(tmp_path), env={})
    assert config.audit_segment_bytes == 64 * 1024 * 1024


def test_the_control_plane_defaults_to_64_mib(tmp_path):
    config = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    assert config.audit_segment_bytes == 64 * 1024 * 1024


def test_audit_segment_bytes_is_read_from_both_tomls(tmp_path):
    broker = load_broker_config(
        write(tmp_path, COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = 4096")),
        env={},
    )
    control = load_control_config(
        write_control(
            tmp_path, CONTROL_COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = 8192")
        ),
        env={},
    )
    assert (broker.audit_segment_bytes, control.audit_segment_bytes) == (4096, 8192)


def test_the_two_writers_may_choose_different_segment_bytes(tmp_path):
    """Like `durability` and unlike [audit].path: nothing compares these, and
    nothing should. Whichever writer crosses its own threshold is the one that
    rotates, so a disagreement makes segment sizes irregular -- untidy, not a
    misconfiguration.

    The second test here that pins the ABSENCE of a check, and would fail if
    someone "helpfully" added one.
    """
    broker = load_broker_config(
        write(tmp_path, COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = 0")),
        env={},
    )
    control = load_control_config(write_control(tmp_path, CONTROL_COMPLETE), env={})
    # Rotation off in the broker, on in the control plane, one file. Legal.
    assert broker.audit_segment_bytes == 0
    assert control.audit_segment_bytes == 64 * 1024 * 1024
    assert broker.audit_path == control.audit_path


def test_a_negative_segment_bytes_is_a_config_error(tmp_path):
    """Zero is meaningful -- it disables rotation -- so this rides on
    _positive(..., allow_zero=True) rather than on _positive's default."""
    text = COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + "\nsegment_bytes = -1")
    with pytest.raises(
        ConfigError, match=re.escape("audit.segment_bytes must be zero or greater, got -1")
    ):
        load_broker_config(write(tmp_path, text), env={})


def test_a_non_integer_segment_bytes_is_a_config_error(tmp_path):
    """A size is not a string. `_integer` refuses it before AuditLog ever sees
    it, which matters because the comparison this value feeds would otherwise
    raise TypeError on an append rather than at boot."""
    text = COMPLETE.replace(_AUDIT_SECTION, _AUDIT_SECTION + '\nsegment_bytes = "64MiB"')
    with pytest.raises(
        ConfigError, match=re.escape("audit.segment_bytes must be an integer")
    ):
        load_broker_config(write(tmp_path, text), env={})
