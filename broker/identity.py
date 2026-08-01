"""Task-bound capability tokens.

Asymmetric on purpose: the private key mints, the public key only verifies,
so adding verifiers never grants minting power.

That property is only worth anything if the two keys actually live in
different places. The keypair is generated outside every container (see
scripts/demo.sh) and handed out split: the control plane loads the private
key and is the sole minter; the broker -- the enforcement point the agent can
actually reach -- loads only the public key. A fully compromised broker
therefore still cannot mint a token, because it never holds the material to
sign one.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ISSUER = "warden-broker"
DEFAULT_TTL_SECONDS = 300


class TokenInvalid(Exception):
    """Raised for any token we will not act on: bad signature, expired, malformed."""


@dataclass(frozen=True)
class TaskToken:
    agent_id: str
    task_id: str
    purpose: str
    allowed_tools: tuple[str, ...]
    data_classes: tuple[str, ...]
    counterparties: tuple[str, ...]
    delegated_from: str | None
    exp: int
    jti: str


class Signer:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        issuer: str = ISSUER,
        default_ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._private_key = private_key
        # These two are configured, not hardcoded: warden.toml's [tokens]
        # and control.toml's [tokens] both carry an issuer (they must agree,
        # or every token fails verification -- loud, not silent), and
        # ttl_seconds is control.toml's alone, since the broker never mints.
        # The module constants above remain only as the default for direct
        # construction (tests, cli/explain.py's standalone demo signer); a
        # configured value always wins when one is supplied.
        self._issuer = issuer
        self._default_ttl_seconds = default_ttl_seconds

    @classmethod
    def generate(cls, *, issuer: str = ISSUER, default_ttl_seconds: int = DEFAULT_TTL_SECONDS) -> "Signer":
        return cls(Ed25519PrivateKey.generate(), issuer=issuer, default_ttl_seconds=default_ttl_seconds)

    @classmethod
    def from_private_key_file(
        cls, path: Path | str, *, issuer: str = ISSUER, default_ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> "Signer":
        """Loads the minting key from disk.

        The type check is not decoration: an RSA or EC key here would load
        cleanly and then fail at the first mint, i.e. at request time, in the
        one process whose only job is minting. Failing at startup instead
        makes a misprovisioned control plane refuse to serve at all.
        """
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
        return cls(key, issuer=issuer, default_ttl_seconds=default_ttl_seconds)

    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def mint(
        self,
        *,
        agent_id: str,
        task_id: str,
        purpose: str,
        allowed_tools: list[str],
        data_classes: list[str],
        counterparties: list[str],
        ttl_seconds: int | None = None,
        now: int | None = None,
    ) -> str:
        issued_at = int(now if now is not None else time.time())
        ttl = self._default_ttl_seconds if ttl_seconds is None else ttl_seconds
        claims = {
            "iss": self._issuer,
            "sub": f"agent:{agent_id}",
            "agent_id": agent_id,
            "task_id": task_id,
            "purpose": purpose,
            "allowed_tools": list(allowed_tools),
            "data_classes": list(data_classes),
            "counterparties": list(counterparties),
            "delegated_from": None,
            "iat": issued_at,
            "exp": issued_at + ttl,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self._private_key, algorithm="EdDSA")


class Verifier:
    def __init__(self, public_key_pem: bytes, *, issuer: str = ISSUER) -> None:
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("verifier requires an Ed25519 public key")
        self._public_key = key
        # Configured, not hardcoded -- see the matching note on Signer. A
        # token whose "iss" does not match this exact string is rejected,
        # which is what makes a warden.toml/control.toml issuer mismatch a
        # loud, total verification failure rather than a silent no-op.
        self._issuer = issuer

    @classmethod
    def from_public_key_file(cls, path: Path | str, *, issuer: str = ISSUER) -> "Verifier":
        """Loads the verification key from disk.

        This is the only key material the broker process ever touches. There
        is deliberately no corresponding loader for a private key here that
        the broker could reach for by accident: the enforcement point verifies
        and never mints.
        """
        return cls(Path(path).read_bytes(), issuer=issuer)

    def verify(self, token: str, now: int | None = None) -> TaskToken:
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=["EdDSA"],
                issuer=self._issuer,
                options={"require": ["exp", "iss", "jti"], "verify_exp": False},
            )
        except jwt.PyJWTError as exc:
            raise TokenInvalid(str(exc)) from exc

        # PyJWT's own exp check is disabled above (verify_exp: False) so that
        # the caller-supplied clock is the single source of expiry truth;
        # this manual check is what actually enforces the TTL.
        reference = int(now if now is not None else time.time())
        if reference > int(claims["exp"]):
            raise TokenInvalid("token expired")

        return TaskToken(
            agent_id=claims["agent_id"],
            task_id=claims["task_id"],
            purpose=claims["purpose"],
            allowed_tools=tuple(claims["allowed_tools"]),
            data_classes=tuple(claims["data_classes"]),
            counterparties=tuple(claims["counterparties"]),
            delegated_from=claims.get("delegated_from"),
            exp=int(claims["exp"]),
            jti=claims["jti"],
        )
