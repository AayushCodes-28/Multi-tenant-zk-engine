import pytest

from src.crypto_engine import AESCBCCipher, CryptographicError, KeyMaterial, TrapdoorGenerator


def test_aes_round_trip_and_random_iv() -> None:
    key = bytes(range(32))
    cipher = AESCBCCipher(key, "tenant-a")
    first = cipher.encrypt("sensitive text")
    second = cipher.encrypt("sensitive text")
    assert cipher.decrypt(first) == "sensitive text"
    assert first.ciphertext != second.ciphertext


def test_aes_rejects_tampering_and_cross_tenant_use() -> None:
    key = bytes(range(32))
    envelope = AESCBCCipher(key, "tenant-a").encrypt("secret")
    with pytest.raises(CryptographicError, match="authentication"):
        AESCBCCipher(key, "tenant-b").decrypt(envelope)
    tampered = envelope.to_dict()
    tampered["ciphertext"] = ("A" if tampered["ciphertext"][0] != "A" else "B") + tampered["ciphertext"][1:]
    with pytest.raises(CryptographicError):
        AESCBCCipher(key, "tenant-a").decrypt(tampered)


def test_trapdoors_are_stable_and_tenant_scoped() -> None:
    key = b"s" * 32
    assert TrapdoorGenerator(key, "a").create("Payroll") == TrapdoorGenerator(key, "a").create("payroll")
    assert TrapdoorGenerator(key, "a").create("payroll") != TrapdoorGenerator(key, "b").create("payroll")


def test_rejects_short_paillier_key() -> None:
    with pytest.raises(ValueError, match="at least 1024"):
        KeyMaterial.generate("tenant", paillier_bits=512)

