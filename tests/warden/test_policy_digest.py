"""policy_bundle_digest's file-root branch, untested until now.

POLICY_DATA in local runs (demo/cli/explain.py, the test suite's own local
`opa run`) is a FILE root, not a directory: data.json sits beside tools.toml,
warden.toml and control.toml, files that are not part of what OPA loads, so
a file root names just that one file. Nothing asserted that changing its
content actually changes the digest -- which is the module's entire reason
to exist: a digest that does not move when the policy does would let an
operator change max_rows_per_task and have every audit record still claim
the identical policy.
"""

from __future__ import annotations

from warden.broker.policy_digest import policy_bundle_digest


def test_a_file_roots_content_change_changes_the_digest(tmp_path):
    data_file = tmp_path / "data.json"
    data_file.write_text('{"limits": {"max_rows_per_task": 50}}')

    before = policy_bundle_digest([data_file])
    data_file.write_text('{"limits": {"max_rows_per_task": 5000000}}')
    after = policy_bundle_digest([data_file])

    assert before != after


def test_a_file_root_is_keyed_by_its_own_name_not_a_directory_relative_path(tmp_path):
    """Two differently-shaped roots covering the identical bytes under the
    identical filename must digest identically -- a file root has no
    "relative to a directory" of its own, so its bare name is exactly as
    safe here as it would be unsafe for a directory root's nested file."""
    as_directory = tmp_path / "as_directory"
    as_directory.mkdir()
    (as_directory / "data.json").write_text('{"x": 1}')

    as_file = tmp_path / "as_file" / "data.json"
    as_file.parent.mkdir()
    as_file.write_text('{"x": 1}')

    assert policy_bundle_digest([as_directory]) == policy_bundle_digest([as_file])
