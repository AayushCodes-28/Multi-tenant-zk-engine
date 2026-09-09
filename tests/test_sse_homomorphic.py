from phe import paillier

from src.crypto_engine import TrapdoorGenerator
from src.homomorphic import HomomorphicAccumulator
from src.sse_engine import EncryptedInvertedIndex


def test_blind_index_search() -> None:
    generator = TrapdoorGenerator(b"x" * 32, "tenant-a")
    payroll = generator.create("payroll")
    index = EncryptedInvertedIndex("tenant-a")
    index.add_document("doc-1", [payroll, generator.create("quarterly")])
    index.add_document("doc-2", [payroll])
    assert index.search(payroll) == ("doc-1", "doc-2")
    assert index.search(generator.create("missing")) == ()
    assert "payroll" not in str(index.to_dict())


def test_paillier_ciphertext_accumulator() -> None:
    public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
    values = [public_key.encrypt(value) for value in (12, -4, 31)]
    encrypted_total = HomomorphicAccumulator(public_key).sum_encrypted(values)
    assert private_key.decrypt(encrypted_total) == 39


def test_empty_accumulator_is_encrypted_zero() -> None:
    public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
    assert private_key.decrypt(HomomorphicAccumulator(public_key).sum_encrypted([])) == 0

