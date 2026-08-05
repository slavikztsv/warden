"""The MCP surface: mounted, authenticated, and off unless asked for."""

from __future__ import annotations

import pytest

mcp = pytest.importorskip("mcp", reason="requires the warden[mcp] extra")


def test_telemetry_is_a_no_op_after_the_broker_boots():
    from opentelemetry import trace

    from warden.broker.__main__ import _silence_telemetry

    _silence_telemetry()
    provider = trace.get_tracer_provider()
    assert type(provider).__name__ == "NoOpTracerProvider"
