"""The MCP surface: mounted, authenticated, and off unless asked for."""

from __future__ import annotations

import pytest

mcp = pytest.importorskip("mcp", reason="requires the warden[mcp] extra")


def test_telemetry_is_a_no_op_after_the_broker_boots(monkeypatch):
    """The happy path: nothing has claimed the process-global TracerProvider
    yet, so _silence_telemetry() both installs the no-op and sees it stick.

    OTel's global provider is a process-wide set-once (the first caller in
    the PROCESS wins, not the first caller in this test), and dozens of
    other tests in this suite call build() -- and therefore
    _silence_telemetry() -- earlier in collection order. Left alone, this
    test would pass regardless of whether THIS call succeeded, because an
    earlier call already won the Once and installed the same provider type.
    Resetting OTel's globals first makes the outcome depend on this call.
    """
    from opentelemetry import trace
    from opentelemetry.trace import NoOpTracerProvider
    from opentelemetry.util._once import Once

    from warden.broker.__main__ import _silence_telemetry

    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", Once())

    _silence_telemetry()

    assert type(trace.get_tracer_provider()) is NoOpTracerProvider


def test_silence_telemetry_refuses_to_start_if_a_provider_got_there_first(monkeypatch):
    """The defeat path: something else -- opentelemetry-instrument, a
    Kubernetes OTel Operator webhook, a site-wide sitecustomize.py -- won
    the process-global set-once before the broker's own code ran.
    set_tracer_provider() then silently no-ops (it logs a warning and
    raises nothing), so _silence_telemetry() must check the outcome itself
    and refuse to start rather than let the broker boot believing telemetry
    is silenced while a live exporter stays installed.
    """
    from opentelemetry import trace
    from opentelemetry.util._once import Once

    from warden.broker.__main__ import _silence_telemetry
    from warden.broker.config.loader import ConfigError

    class FakeRealProvider(trace.TracerProvider):
        def get_tracer(self, *args, **kwargs):
            return trace.NoOpTracer()

    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", Once())
    trace.set_tracer_provider(FakeRealProvider())

    with pytest.raises(ConfigError):
        _silence_telemetry()


def test_silence_telemetry_still_passes_on_a_repeated_call_in_the_same_process():
    """The suite calls build() -- and therefore _silence_telemetry() --
    many times in one process. After the first call wins the Once and
    installs the no-op, every later call must still see a no-op provider
    and PASS, even though its own set_tracer_provider() call is a no-op
    that logs "Overriding of current TracerProvider is not allowed". The
    check has to be "is the current provider a no-op", not "did MY call
    win the Once" -- the latter would fail every test after the first.

    Deliberately does not reset OTel's globals first. That makes this test
    order-independent rather than order-dependent: whatever the first call
    below finds -- untouched state (it wins the Once itself) or a
    NoOpTracerProvider some earlier test's build() already installed (it
    loses the Once, silently) -- the outcome check must find a no-op
    provider either way, or this whole suite already failed earlier. The
    second call is then guaranteed to be the repeated, Once-losing case
    that production's many build() calls hit, and must still pass.
    """
    from opentelemetry import trace
    from opentelemetry.trace import NoOpTracerProvider

    from warden.broker.__main__ import _silence_telemetry

    _silence_telemetry()
    _silence_telemetry()

    assert type(trace.get_tracer_provider()) is NoOpTracerProvider
