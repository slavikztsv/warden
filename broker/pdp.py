"""Client for the policy decision point.

Every failure mode denies. An unreachable or incoherent PDP means no decision
can be made, and no decision means no action.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

# Order matters: the first failing rule in this list is what gets reported.
# egress.allowlist outranks egress.pii_sink so that a pii_sink denial in the
# audit log always means the destination genuinely passed the allowlist.
DENY_PRECEDENCE = (
    "input.malformed",
    "tools.allowed",
    "egress.allowlist",
    "egress.pii_sink",
    "rows.bounded",
    # Below rows.bounded on purpose: a bulk read breaches both, and the volume
    # breach is the one worth naming. rows.scope is then unambiguous -- it can
    # only be reported for a read that was within budget and still out of scope.
    "rows.scope",
    "mail.counterparty",
)

UNAVAILABLE = "pdp.unavailable"


@dataclass(frozen=True)
class Decision:
    allow: bool
    rule: str


class PolicyDecisionPoint:
    def __init__(
        self, base_url: str, *, decision_path: str = "warden/authz", client: httpx.Client
    ) -> None:
        self._url = f"{base_url.rstrip('/')}/v1/data/{decision_path.strip('/')}"
        self._client = client

    def decide(self, input_doc: dict) -> Decision:
        try:
            response = self._client.post(self._url, json={"input": input_doc})
            response.raise_for_status()
            result = response.json()["result"]
            allow = result["allow"]
            reasons = result["deny_reasons"]
        except (httpx.HTTPError, KeyError, ValueError, TypeError):
            return Decision(allow=False, rule=UNAVAILABLE)

        if not isinstance(reasons, list):
            return Decision(allow=False, rule=UNAVAILABLE)

        # Only the exact boolean True, paired with an empty reasons list, is
        # trusted as an affirmative decision. allow=True alongside a
        # non-empty deny_reasons is internally contradictory -- treated the
        # same as any other incoherent response: deny, and say so. A truthy
        # stand-in ("true", 1, ...) instead of the literal boolean is also
        # not trusted; a real OPA response never sends one.
        if allow is True:
            if reasons:
                return Decision(allow=False, rule=UNAVAILABLE)
            return Decision(allow=True, rule="allow")

        for rule in DENY_PRECEDENCE:
            if rule in reasons:
                return Decision(allow=False, rule=rule)
        return Decision(allow=False, rule=UNAVAILABLE)
