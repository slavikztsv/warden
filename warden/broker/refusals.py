"""What a caller is told, once, for every Outcome that is not a success.

Two front doors render the same Outcome -- warden/broker/app.py over HTTP,
warden/broker/mcp.py over MCP. They choose their own status codes and their
own error channels; that is what a surface is for. They must not choose their
own WORDS, because the words are where the security-relevant part lives:
whether a record exists, whether the action already happened, and whether
anything of the deployment's internals is in the sentence.

Five kinds carry `str(exc)` in Outcome.message, and the two live sources of
one are the audit log's own filesystem errors -- which name the audit path --
and the adapters' HTTP client, which names internal hosts. Neither is
rendered anywhere. These constants are what gets rendered instead, and they
live here rather than in either surface so that a correction to one wording
is a correction to both. A surface that owned its own copy would be free to
keep leaking after the other stopped, which is exactly what happened: the
HTTP door emitted the audit path in a 503 for a whole task after the MCP door
had stopped.

Nothing here imports a wire protocol, a web framework or an SDK. app.py has
to be able to read it with the MCP extra absent.
"""

from __future__ import annotations

from warden.broker.spine import FAULT, Kind

# Every fault except DESCRIBE_BACKEND_FAULT left exactly one durable allow
# record for an action that may already have happened -- see FAULT's comment
# in spine.py. Derived rather than listed on purpose: a fault added to that
# set later renders as "do not repeat", which is the safe direction to be
# wrong in, instead of falling through to a generic branch and inviting a
# retry.
AFTER_EXECUTE = FAULT - {Kind.DESCRIBE_BACKEND_FAULT}

UNAUTHENTICATED_MESSAGE = (
    "Unauthenticated. Present a task token as an Authorization: Bearer "
    "credential."
)

# Accurate about the one thing that matters here: nothing was decided, so
# nothing was done. A retry is safe once the log is writable again.
AUDIT_UNAVAILABLE_MESSAGE = (
    "The broker cannot record decisions, so it is not making any. No tool ran."
)

# DESCRIBE_BACKEND_FAULT only. The spine returns that kind from a branch that
# provably writes nothing and executes nothing (a describe() that raised
# before any decision), so this is the one fault that can honestly say so.
NOTHING_RAN = (
    "The tool could not be completed. No tool ran, and nothing was recorded "
    "against this call."
)

# For a failure in the RENDERER, or an Outcome kind no surface has a branch
# for. Deliberately claims neither that a record exists nor that one does not:
# by the time a rendering fails, the spine has already run and may have
# executed and recorded anything. The earlier wording here asserted "The
# failure was recorded" on paths where nothing was recorded and -- because an
# MCPError is mapped straight to the wire without going through the SDK's
# logging branch -- nothing was logged either. Both surfaces now log these
# themselves.
UNEXPECTED_FAULT = (
    "The tool could not be completed. The broker logged the failure. Whether "
    "the action took effect is not known here, so do not repeat this call "
    "without checking."
)

AFTER_THE_FACT = (
    "The tool could not be completed, and the action it authorised may "
    "already have been performed. Do not repeat this call."
)


def after_the_fact(audit_seq: int | None) -> str:
    """The post-execute warning, with a handle on what already happened.

    One function rather than an f-string at each call site, so both surfaces
    name the record the same way. A caller that must not retry needs to be
    able to find the allow record that stands as the account of the action --
    that record is the only thing that was written, because the spine
    deliberately does not add a second one for a failure that came after it.
    """
    return f"{AFTER_THE_FACT} (audit record {audit_seq})"
