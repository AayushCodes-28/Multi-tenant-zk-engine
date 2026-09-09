"""Client-side cryptographic primitives.

The classes in this module belong on the trusted client.  Server components only
receive authenticated ciphertext envelopes, Paillier public keys/ciphertexts,
and opaque HMAC trapdoors.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from phe import paillier
from phe.paillier import EncryptedNumber, PaillierPrivateKey, PaillierPublicKey


class CryptographicError(ValueError):
    """Raised when cryptographic input or authentication is invalid."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise CryptographicError("Invalid base64 in ciphertext envelope") from exc


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    """Per-tenant secrets and Paillier key pair held by the client."""

    tenant_id: str
    aes_master_key: bytes
    search_key: bytes
    public_key: PaillierPublicKey
    private_key: PaillierPrivateKey

    @classmethod
    def generate(cls, tenant_id: str, *, paillier_bits: int = 2048) -> "KeyMaterial":
        """Generate independent symmetric keys and a Paillier key pair."""
        if not tenant_id.strip():
            raise ValueError("tenant_id must not be empty")
        if paillier_bits < 1024:
            raise ValueError("Paillier keys must be at least 1024 bits")
        public_key, private_key = paillier.generate_paillier_keypair(n_length=paillier_bits)
        return cls(tenant_id, get_random_bytes(32), get_random_bytes(32), public_key, private_key)


@dataclass(frozen=True, slots=True)
class CiphertextEnvelope:
    """Serializable AES-CBC encrypt-then-MAC envelope."""

    version: int
    algorithm: str
    iv: str
    ciphertext: str
    mac: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "iv": self.iv,
            "ciphertext": self.ciphertext,
            "mac": self.mac,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CiphertextEnvelope":
        try:
            return cls(
                version=int(value["version"]),
                algorithm=str(value["algorithm"]),
                iv=str(value["iv"]),
                ciphertext=str(value["ciphertext"]),
                mac=str(value["mac"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CryptographicError("Malformed ciphertext envelope") from exc


class AESCBCCipher:
    """AES-256-CBC with PKCS#7 padding and encrypt-then-MAC authentication.

    CBC alone is malleable. Separate encryption and authentication subkeys are
    derived from a 256-bit master key, and the tenant ID is authenticated to
    prevent cross-tenant ciphertext substitution.
    """

    VERSION = 1
    ALGORITHM = "AES-256-CBC+HMAC-SHA256"

    def __init__(self, master_key: bytes, tenant_id: str) -> None:
        if len(master_key) != 32:
            raise ValueError("AES master key must be exactly 32 bytes")
        if not tenant_id:
            raise ValueError("tenant_id must not be empty")
        self._tenant_id = tenant_id
        context = tenant_id.encode("utf-8")
        expanded = HKDF(master_key, 64, b"zkce-aes-v1", SHA256, context=context)
        self._encryption_key, self._mac_key = expanded[:32], expanded[32:]

    def encrypt(self, plaintext: str) -> CiphertextEnvelope:
        """Encrypt and authenticate UTF-8 text using a fresh random IV."""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be a string")
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self._encryption_key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        tag = hmac.new(self._mac_key, self._mac_input(iv, ciphertext), hashlib.sha256).digest()
        return CiphertextEnvelope(self.VERSION, self.ALGORITHM, _b64encode(iv), _b64encode(ciphertext), _b64encode(tag))

    def decrypt(self, envelope: CiphertextEnvelope | Mapping[str, Any]) -> str:
        """Authenticate then decrypt an envelope; never decrypts invalid input."""
        if not isinstance(envelope, CiphertextEnvelope):
            envelope = CiphertextEnvelope.from_dict(envelope)
        if envelope.version != self.VERSION or envelope.algorithm != self.ALGORITHM:
            raise CryptographicError("Unsupported ciphertext envelope")
        iv, ciphertext, supplied_tag = map(_b64decode, (envelope.iv, envelope.ciphertext, envelope.mac))
        if len(iv) != AES.block_size or not ciphertext or len(ciphertext) % AES.block_size:
            raise CryptographicError("Invalid AES-CBC ciphertext dimensions")
        expected_tag = hmac.new(self._mac_key, self._mac_input(iv, ciphertext), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_tag, supplied_tag):
            raise CryptographicError("Ciphertext authentication failed")
        try:
            padded = AES.new(self._encryption_key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
            return unpad(padded, AES.block_size).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise CryptographicError("Ciphertext could not be decrypted") from exc

    def _mac_input(self, iv: bytes, ciphertext: bytes) -> bytes:
        return b"zkce:v1\x00" + self._tenant_id.encode("utf-8") + b"\x00" + iv + ciphertext


def normalize_term(term: str) -> str:
    """Normalize one search term deterministically on the trusted client."""
    return unicodedata.normalize("NFKC", term).casefold().strip()


def tokenize(text: str) -> set[str]:
    """Extract normalized Unicode word tokens for client-side indexing."""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return {token for token in re.findall(r"[^\W_]+", normalized, flags=re.UNICODE) if token}


class TrapdoorGenerator:
    """Create deterministic, tenant-bound HMAC-SHA256 search trapdoors."""

    def __init__(self, search_key: bytes, tenant_id: str) -> None:
        if len(search_key) < 32:
            raise ValueError("search key must contain at least 32 bytes")
        if not tenant_id:
            raise ValueError("tenant_id must not be empty")
        self._search_key = search_key
        self._prefix = b"zkce:sse:v1\x00" + tenant_id.encode("utf-8") + b"\x00"

    def create(self, term: str) -> str:
        terms = tokenize(term)
        if len(terms) != 1:
            raise ValueError("search term must be one non-empty token")
        normalized = next(iter(terms))
        return hmac.new(self._search_key, self._prefix + normalized.encode("utf-8"), hashlib.sha256).hexdigest()


class PaillierClient:
    """Trusted-client wrapper for Paillier encryption and decryption."""

    def __init__(self, public_key: PaillierPublicKey, private_key: PaillierPrivateKey) -> None:
        if private_key.public_key.n != public_key.n:
            raise ValueError("Paillier public/private keys do not match")
        self.public_key = public_key
        self._private_key = private_key

    def encrypt_integer(self, value: int) -> EncryptedNumber:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("demo accumulator accepts integer values only")
        return self.public_key.encrypt(value)

    def decrypt_integer(self, value: EncryptedNumber) -> int:
        result = self._private_key.decrypt(value)
        if not isinstance(result, int):
            raise CryptographicError("Expected an integer Paillier plaintext")
        return result
