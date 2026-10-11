from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from .access_control import UserAttributes


class TokenError(ValueError):
    pass


def _enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True, slots=True)
class Claims:
    jti: str
    user: UserAttributes
    issued_at: float
    expires_at: float


class Authority:
    def __init__(self, seed: bytes) -> None:
        self._key = eddsa.import_private_key(seed)
        self.seed = seed

    @classmethod
    def generate(cls) -> "Authority":
        return cls(os.urandom(32))

    @classmethod
    def load_or_create(cls, path: str | Path) -> "Authority":
        path = Path(path)
        if path.exists():
            return cls(bytes.fromhex(path.read_text().strip()))
        authority = cls.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(authority.seed.hex())
        return authority

    @property
    def public_key(self) -> bytes:
        return self._key.public_key().export_key(format="raw")

    def issue(self, user: UserAttributes, *, ttl: int = 900, now: float | None = None) -> str:
        issued = time.time() if now is None else now
        payload = json.dumps(
            {
                "v": 1,
                "jti": secrets.token_hex(8),
                "sub": user.subject_id,
                "ten": user.tenant_id,
                "role": user.role,
                "dep": user.department,
                "clr": user.clearance_level,
                "iat": issued,
                "exp": issued + ttl,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        signature = eddsa.new(self._key, "rfc8032").sign(payload)
        return f"{_enc(payload)}.{_enc(signature)}"


def verify_token(token: str, public_key: bytes, *, now: float | None = None) -> Claims:
    try:
        payload_text, signature_text = token.split(".")
        payload, signature = _dec(payload_text), _dec(signature_text)
        eddsa.new(eddsa.import_public_key(public_key), "rfc8032").verify(payload, signature)
        data = json.loads(payload)
        user = UserAttributes(data["sub"], data["ten"], data["role"], data["dep"], int(data["clr"]))
        claims = Claims(data["jti"], user, float(data["iat"]), float(data["exp"]))
    except (ValueError, KeyError, TypeError) as exc:
        raise TokenError("invalid capability token") from exc
    if (time.time() if now is None else now) >= claims.expires_at:
        raise TokenError("capability token expired")
    return claims