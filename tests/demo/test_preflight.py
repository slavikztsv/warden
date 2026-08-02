"""What the menu is allowed to claim is runnable.

The provider precedence here must match demo/agent/llm.py's
live_client_from_env exactly -- openrouter, then gemini, with
WARDEN_PROVIDER overriding outright. A menu that labels a run "ready" and
then dies on a missing credential is worse than no label at all.
"""

from __future__ import annotations

from pathlib import Path

from demo.cli import preflight

LLM_SOURCE = (
    Path(__file__).resolve().parent.parent.parent / "demo" / "agent" / "llm.py"
).read_text()


def test_the_key_names_match_the_agent_runtime():
    """preflight duplicates llm.py's credential table, because importing that
    module drags in the vendor SDKs a preflight check must not require. Pin
    the names to its source so a rename there cannot leave the menu happily
    labelling a credential nothing reads any more."""
    for key in preflight.LIVE_KEYS.values():
        assert key in LLM_SOURCE, key
    assert "WARDEN_PROVIDER" in LLM_SOURCE


def test_the_precedence_order_matches_the_agent_runtime():
    positions = [LLM_SOURCE.index(f'"{name}"') for name in preflight.PRECEDENCE]
    assert positions == sorted(positions), (
        "preflight.PRECEDENCE no longer matches the order llm.py declares"
    )


def test_no_credential_anywhere_means_no_provider():
    assert preflight.live_provider({}) is None


def test_each_key_on_its_own_selects_its_provider():
    assert preflight.live_provider({"OPENROUTER_API_KEY": "k"}) == "openrouter"
    assert preflight.live_provider({"GEMINI_API_KEY": "k"}) == "gemini"


def test_precedence_matches_the_agent_runtime():
    """openrouter wins, then gemini -- the order live_client_from_env uses."""
    every = {
        "OPENROUTER_API_KEY": "k",
        "GEMINI_API_KEY": "k",
    }
    assert preflight.live_provider(every) == "openrouter"
    assert preflight.live_provider({k: v for k, v in every.items() if "OPENROUTER" not in k}) == "gemini"


def test_warden_provider_overrides_the_precedence():
    env = {"OPENROUTER_API_KEY": "k", "GEMINI_API_KEY": "k", "WARDEN_PROVIDER": "gemini"}
    assert preflight.live_provider(env) == "gemini"


def test_warden_provider_without_its_key_is_not_runnable():
    """llm.py raises here rather than falling back, so neither may the menu."""
    env = {"OPENROUTER_API_KEY": "k", "WARDEN_PROVIDER": "gemini"}
    assert preflight.live_provider(env) is None


def test_an_unknown_warden_provider_is_not_runnable():
    assert preflight.live_provider({"OPENROUTER_API_KEY": "k", "WARDEN_PROVIDER": "nope"}) is None


def test_blank_values_do_not_count_as_credentials():
    assert preflight.live_provider({"OPENROUTER_API_KEY": "   "}) is None


def test_dotenv_is_read_when_the_process_environment_has_nothing(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=from-the-file\n# a comment\nGEMINI_API_KEY=\n")
    merged = preflight.merged_env({}, dotenv_path=env_file)
    assert merged["OPENROUTER_API_KEY"] == "from-the-file"
    assert preflight.live_provider(merged) == "openrouter"


def test_the_process_environment_beats_the_dotenv_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=from-the-file\n")
    merged = preflight.merged_env({"OPENROUTER_API_KEY": "from-the-process"}, dotenv_path=env_file)
    assert merged["OPENROUTER_API_KEY"] == "from-the-process"


def test_a_missing_dotenv_is_not_an_error(tmp_path):
    assert preflight.merged_env({}, dotenv_path=tmp_path / "absent") == {}


def test_dotenv_quotes_are_stripped(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text('OPENROUTER_API_KEY="quoted"\n')
    assert preflight.merged_env({}, dotenv_path=env_file)["OPENROUTER_API_KEY"] == "quoted"


def test_docker_availability_follows_the_resolver():
    assert preflight.docker_available(which=lambda _: "/usr/bin/docker") is True
    assert preflight.docker_available(which=lambda _: None) is False
