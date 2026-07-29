"""Task-bound capability tokens.

Asymmetric on purpose: the private key mints, the public key only verifies,
so adding verifiers never grants minting power.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

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
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now: int | None = None,
    ) -> str:
        issued_at = int(now if now is not None else time.time())
        claims = {
            "iss": ISSUER,
            "sub": f"agent:{agent_id}",
            "agent_id": agent_id,
            "task_id": task_id,
            "purpose": purpose,
            "allowed_tools": list(allowed_tools),
            "data_classes": list(data_classes),
            "counterparties": list(counterparties),
            "delegated_from": None,
            "iat": issued_at,
            "exp": issued_at + ttl_seconds,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self._private_key, algorithm="EdDSA")


class Verifier:
    def __init__(self, public_key_pem: bytes) -> None:
        self._public_key = serialization.load_pem_public_key(public_key_pem)

    def verify(self, token: str, now: int | None = None) -> TaskToken:
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=["EdDSA"],
                issuer=ISSUER,
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
