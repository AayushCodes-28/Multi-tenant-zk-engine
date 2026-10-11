from __future__ import annotations

from collections.abc import Callable, Iterable
import secrets
from phe.paillier import EncryptedNumber, PaillierPublicKey

ProgressCallback = Callable[[int, int, str], None]

class HomomorphicAccumulator:
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

    @staticmethod
    def aggregate_raw(public_key: PaillierPublicKey, ciphertexts: list[int], weights: list[int] | None = None) -> int:
        modulus = public_key.nsquare
        if weights is not None and len(weights) != len(ciphertexts):
            raise ValueError("one weight per ciphertext is required")
        accumulator = 1
        for position, ciphertext in enumerate(ciphertexts):
            if not 0 < ciphertext < modulus:
                raise ValueError("ciphertext out of range")
            weight = 1 if weights is None else weights[position]
            # if isinstance(weight, bool) or not isinstance(weight, int):
            #     raise ValueError("weights must be integers")
            accumulator = accumulator * pow(ciphertext, weight, modulus) % modulus
        blind = pow(secrets.randbelow(public_key.n - 1) + 1, public_key.n, modulus)
        return accumulator * blind % modulus
