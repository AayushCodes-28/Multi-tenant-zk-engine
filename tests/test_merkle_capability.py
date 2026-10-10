import time

import pytest

from src.access_control import UserAttributes
from src.audit import AuditLog
from src.capability import Authority, TokenError, verify_token
from src.merkle import ProofError, SparseMerkle, empty_root, updated_root, verify


def test_membership_absence_and_update_roots():
    tree = SparseMerkle()
    assert tree.root == empty_root()
    root = tree.set("a", b"1" * 32)
    assert verify(root, "a", tree.prove("a")) == b"1" * 32
    assert verify(root, "missing", tree.prove("missing")) is None
    predicted = updated_root(root, "b", b"2" * 32, tree.prove("b"))
    assert predicted == tree.set("b", b"2" * 32)
    assert tree.set("b", None) == root


def test_proof_rejects_wrong_root_and_tampered_bucket():
    tree = SparseMerkle()
    root = tree.set("a", b"1" * 32)
    proof = tree.prove("a")
    with pytest.raises(ProofError):
        verify(b"\x00" * 32, "a", proof)
    proof["bucket"][0][1] = (b"9" * 32).hex()
    with pytest.raises(ProofError):
        verify(root, "a", proof)


def test_token_round_trip_expiry_and_tamper():
    authority = Authority.generate()
    user = UserAttributes("u", "t", "analyst", "finance", 2)
    token = authority.issue(user, ttl=60)
    assert verify_token(token, authority.public_key).user == user
    with pytest.raises(TokenError):
        verify_token(token, authority.public_key, now=time.time() + 120)
    with pytest.raises(TokenError):
        verify_token(token, Authority.generate().public_key)
    head, tail = token.split(".")
    with pytest.raises(TokenError):
        verify_token(("A" if head[0] != "A" else "B") + head[1:] + "." + tail, authority.public_key)


def test_audit_chain_is_tamper_evident():
    log = AuditLog()
    for index in range(4):
        log.append(action="search", decision="ALLOW", n=index)
    assert log.verify() == (True, None)
    log.entries[2]["decision"] = "DENY"
    assert log.verify() == (False, 2)
    del log.entries[1]
    assert log.verify()[0] is False