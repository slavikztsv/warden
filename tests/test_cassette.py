"""The demo replays this exact file. Nothing else in the suite reads it."""

import json
from pathlib import Path

from agent.tools import TOOL_SCHEMAS
from tests.support.catalog import demo_catalog

CATALOG = demo_catalog(
    docstore_url="http://d", db_path="data/customers.db", mailer_url="http://m", client=None
)

CASSETTE = Path("agent/cassettes/support-triage.json")
EXPECTED = [
    "read_document",
    "read_document",
    "query_customers",
    "query_customers",
    "http_fetch",
    "http_fetch",
    "send_email",
]


def steps():
    return json.loads(CASSETTE.read_text())


def test_the_cassette_is_valid_json_ending_in_a_final_step():
    recorded = steps()
    assert recorded[-1]["type"] == "final"
    assert recorded[-1]["text"]


def test_every_tool_is_one_the_agent_actually_has():
    names = {schema["name"] for schema in TOOL_SCHEMAS}
    assert [s["tool"] for s in steps() if s["type"] == "tool_use"] == EXPECTED
    assert all(s["tool"] in names for s in steps() if s["type"] == "tool_use")


def test_every_step_would_survive_the_brokers_argument_validation():
    # A malformed step would be denied as input.malformed at runtime, so the
    # demo would report the wrong rule for the wrong reason.
    for step in steps():
        if step["type"] == "tool_use":
            assert CATALOG.validate(step["tool"], step["args"]), step


def test_both_exfiltration_attempts_carry_a_body():
    # Without a body the sinkhole records zero bytes and beat 1 of the demo
    # has nothing to show.
    exfil = [s for s in steps() if s["type"] == "tool_use" and s["tool"] == "http_fetch"]
    assert len(exfil) == 2
    assert all(isinstance(s["args"].get("body"), str) and s["args"]["body"] for s in exfil)


def test_the_fallback_targets_an_allowlisted_host():
    # docstore.internal is ON the egress allowlist; only taint stops it. If this
    # ever changed to a non-allowlisted host, the demo would prove nothing that
    # an ordinary gateway could not.
    urls = [s["args"]["url"] for s in steps() if s.get("tool") == "http_fetch"]
    assert any("attacker.example" in u for u in urls)
    assert any("docstore.internal" in u for u in urls)
