"""Server-side Paillier additive homomorphic accumulator."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from phe.paillier import EncryptedNumber, PaillierPublicKey

ProgressCallback = Callable[[int, int, str], None]


class HomomorphicAccumulator:
    """Add encrypted integers by multiplying ciphertexts modulo ``n²``.

    In Paillier, ``D(E(a) * E(b) mod n²) = a + b mod n``. The server only
    needs the public key and never receives the private key.
    """

    def __init__(self, public_key: PaillierPublicKey) -> None:
        self.public_key = public_key

    def sum_encrypted(
        self,
        values: Iterable[EncryptedNumber],
        *,
        on_step: ProgressCallback | None = None,
    ) -> EncryptedNumber:
        items = list(values)
        if not items:
            return self.public_key.encrypt(0)
        exponent = items[0].exponent
        accumulator = 1
        modulus = self.public_key.nsquare
        total = len(items)
        for position, item in enumerate(items, start=1):
            if item.public_key.n != self.public_key.n:
                raise ValueError("ciphertext belongs to a different Paillier key")
            if item.exponent != exponent:
                raise ValueError("all ciphertexts must use the same fixed-point exponent")
            accumulator = (accumulator * item.ciphertext(be_secure=True)) % modulus
            if on_step:
                on_step(position, total, "ciphertext multiplied modulo n²")
        result = EncryptedNumber(self.public_key, accumulator, exponent)
        result.obfuscate()
        return result

