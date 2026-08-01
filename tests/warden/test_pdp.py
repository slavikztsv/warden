import httpx
import pytest

from warden.broker.pdp import Decision, PolicyDecisionPoint
from warden.broker.policy_digest import policy_bundle_digest

INPUT = {
    "principal": {"purpose": "support-triage", "allowed_tools": ["http_fetch"]},
    "action": {"type": "tool_call", "tool": "http_fetch"},
    "target": {"kind": "http", "host": "attacker.example"},
    "task_state": {"data_classes_held": ["pii"], "rows_returned_so_far": 1},
}


def pdp_returning(payload):
    def handler(request):
        return httpx.Response(200, json={"result": payload})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return PolicyDecisionPoint("http://opa:8181", client=client)


def test_allow_when_no_deny_reasons():
    decision = pdp_returning({"allow": True, "deny_reasons": []}).decide(INPUT)
    assert decision == Decision(allow=True, rule="allow")


def test_deny_reports_the_single_failing_rule():
    pdp = pdp_returning({"allow": False, "deny_reasons": ["rows.bounded"]})
    assert pdp.decide(INPUT) == Decision(allow=False, rule="rows.bounded")


def test_multiple_failures_report_the_highest_precedence_rule():
    # An unlisted host that is also a PII violation reports the allowlist,
    # so egress.pii_sink in the log always means the host WAS allowlisted.
    pdp = pdp_returning(
        {"allow": False, "deny_reasons": ["egress.pii_sink", "egress.allowlist"]}
    )
    assert pdp.decide(INPUT).rule == "egress.allowlist"


def test_precedence_is_independent_of_response_order():
    forward = pdp_returning(
        {"allow": False, "deny_reasons": ["rows.bounded", "tools.allowed"]}
    )
    backward = pdp_returning(
        {"allow": False, "deny_reasons": ["tools.allowed", "rows.bounded"]}
    )
    assert forward.decide(INPUT).rule == backward.decide(INPUT).rule == "tools.allowed"


def test_unreachable_opa_fails_closed():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    decision = PolicyDecisionPoint("http://opa:8181", client=client).decide(INPUT)
    assert decision.allow is False
    assert decision.rule == "pdp.unavailable"


def test_malformed_opa_response_fails_closed():
    def handler(request):
        return httpx.Response(200, json={"unexpected": "shape"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    decision = PolicyDecisionPoint("http://opa:8181", client=client).decide(INPUT)
    assert decision.allow is False
    assert decision.rule == "pdp.unavailable"


def test_opa_error_status_fails_closed():
    def handler(request):
        return httpx.Response(500, text="boom")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert PolicyDecisionPoint("http://opa:8181", client=client).decide(INPUT).allow is False


def test_bundle_digest_is_stable_and_content_sensitive(tmp_path):
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    (tmp_path / "data.json").write_text('{"limits": {}}\n')
    first = policy_bundle_digest([tmp_path])
    assert first == policy_bundle_digest([tmp_path])
    assert first.startswith("sha256:")

    (tmp_path / "data.json").write_text('{"limits": {"max_rows_per_task": 50}}\n')
    assert policy_bundle_digest([tmp_path]) != first


def test_bundle_digest_ignores_test_files(tmp_path):
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    before = policy_bundle_digest([tmp_path])
    (tmp_path / "authz_test.rego").write_text("package warden.authz_test\n")
    assert policy_bundle_digest([tmp_path]) == before


def test_bundle_digest_covers_nested_files(tmp_path):
    """iterdir() dropped subdirectories entirely, so a bundle laid out in
    subdirectories was digested as if those files were not there."""
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "data.json").write_text('{"limits": {}}\n')
    before = policy_bundle_digest([tmp_path])
    (nested / "data.json").write_text('{"limits": {"max_rows_per_task": 5000000}}\n')
    assert policy_bundle_digest([tmp_path]) != before


def test_bundle_digest_covers_every_root(tmp_path):
    """The whole reason for the signature change: a bundle split across two
    mounts must be digested as one.  Dropping the data root silently stopped
    the digest covering max_rows_per_task."""
    rules = tmp_path / "rules"
    data = tmp_path / "data"
    rules.mkdir()
    data.mkdir()
    (rules / "authz.rego").write_text("package warden.authz\n")
    (data / "data.json").write_text('{"limits": {"max_rows_per_task": 50}}\n')

    both = policy_bundle_digest([rules, data])
    assert both != policy_bundle_digest([rules])

    (data / "data.json").write_text('{"limits": {"max_rows_per_task": 5000000}}\n')
    assert policy_bundle_digest([rules, data]) != both


def test_bundle_digest_rejects_a_missing_root(tmp_path):
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    with pytest.raises(ValueError, match="does not exist"):
        policy_bundle_digest([tmp_path, tmp_path / "absent"])


def test_bundle_digest_rejects_an_empty_root(tmp_path):
    """An empty root is a mount that did not happen.  Digesting it as the
    empty string would make a missing data.json indistinguishable from a
    data.json that is genuinely absent from the design."""
    (tmp_path / "authz.rego").write_text("package warden.authz\n")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no policy files"):
        policy_bundle_digest([tmp_path, empty])


def test_bundle_digest_depends_on_root_order(tmp_path):
    """Two roots each holding data.json must not hash the same as one root
    holding both contents concatenated.

    NOTE: this only proves the digest is sensitive to the ORDER of the roots
    argument, which holds for any sequential implementation regardless of
    whether it keys each file by root-relative path, bare name, or nothing
    at all. It does not by itself prove same-named files across roots are
    kept apart -- see test_bundle_digest_distinguishes_nested_from_root_level_same_basename
    and test_bundle_digest_is_stable_when_the_mount_point_moves for that."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "data.json").write_text('{"x": 1}\n')
    (b / "data.json").write_text('{"y": 2}\n')
    assert policy_bundle_digest([a, b]) != policy_bundle_digest([b, a])


def test_bundle_digest_distinguishes_nested_from_root_level_same_basename(tmp_path):
    """A file's digest key must include the directories above it within its
    root, not just its bare filename -- otherwise a nested file and a
    root-level file that happen to share a name collapse onto the same
    contribution regardless of where either one actually sits.

    A flat two-root fixture (as in test_bundle_digest_depends_on_root_order)
    can never catch this: relative-path and bare-name keys only diverge once
    a file is nested. So: one root holds sub/x.rego, another holds x.rego at
    its top level, same bytes in both. Under root-relative keying those are
    the distinct keys "sub/x.rego" and "x.rego". Under bare-name keying they
    are both just "x.rego" -- indistinguishable from a root-level file with
    the same name and content.  Comparing against a second pairing that
    replaces the nested file with an equivalent root-level one isolates
    exactly that difference."""
    nested_root = tmp_path / "nested_root"
    flat_root = tmp_path / "flat_root"
    nested_root.mkdir()
    flat_root.mkdir()
    (nested_root / "sub").mkdir()
    (nested_root / "sub" / "x.rego").write_text("package warden.authz\n")
    (flat_root / "x.rego").write_text("package warden.authz\n")
    mixed = policy_bundle_digest([nested_root, flat_root])

    both_flat_root = tmp_path / "both_flat_root"
    both_flat_root.mkdir()
    (both_flat_root / "x.rego").write_text("package warden.authz\n")
    both_flat = policy_bundle_digest([both_flat_root, flat_root])

    assert mixed != both_flat


def test_bundle_digest_is_stable_when_the_mount_point_moves(tmp_path):
    """The digest must depend only on each file's path relative to its own
    root, never on where that root sits in the filesystem -- otherwise the
    same bundle remounted at a different absolute path (a routine container
    operation) would look like a policy change even though not one byte of
    policy changed. This is the property that makes the relative-path key
    correct where a bare absolute-path key would not be."""

    def build_layout(parent):
        root = parent / "policies"
        root.mkdir(parents=True)
        (root / "authz.rego").write_text("package warden.authz\n")
        nested = root / "sub"
        nested.mkdir()
        (nested / "data.json").write_text('{"limits": {}}\n')
        return root

    a = build_layout(tmp_path / "mount_a")
    b = build_layout(tmp_path / "somewhere" / "else" / "mount_b")
    assert policy_bundle_digest([a]) == policy_bundle_digest([b])
