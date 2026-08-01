"""The components both enforcement surfaces share, as a type rather than a dict.

build() used to return an untyped dict splatted into create_app AND
serve_proxy. Their signatures differ and neither takes **kwargs, so every key
had to be a valid keyword of both -- and adding the catalog, which the tool
API needs and the proxy does not, raised TypeError from serve_proxy and took
all egress down. Nothing greppable expressed that constraint.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BrokerComponents:
    verifier: object
    pdp: object
    taint: object
    audit: object
    policy_digest: str

    def as_app_kwargs(self) -> dict:
        return {
            "verifier": self.verifier, "pdp": self.pdp, "taint": self.taint,
            "audit": self.audit, "policy_digest": self.policy_digest,
        }

    def as_proxy_kwargs(self) -> dict:
        return self.as_app_kwargs()
