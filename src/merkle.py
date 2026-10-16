from __future__ import annotations

import hashlib
from typing import Any

DEPTH = 40


class ProofError(ValueError):
    pass


def _sha(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def _defaults() -> list[bytes]:
    levels = [_sha(b"\x00empty")]
    for _ in range(DEPTH):
        levels.append(_sha(b"\x01", levels[-1], levels[-1]))
    return levels


DEFAULTS = _defaults()


def position(key: str) -> int:
    return int.from_bytes(hashlib.sha256(key.encode()).digest()[:5], "big")


def leaf_hash(bucket: dict[str, bytes]) -> bytes:
    if not bucket:
        return DEFAULTS[0]
    parts = [b"\x00"]
    for key in sorted(bucket):
        raw = key.encode()
        parts += [len(raw).to_bytes(2, "big"), raw, bucket[key]]
    return _sha(*parts)


def fold(leaf: bytes, pos: int, siblings: list[bytes]) -> bytes:
    node = leaf
    for level, sibling in enumerate(siblings):
        left, right = (node, sibling) if not (pos >> level) & 1 else (sibling, node)
        node = _sha(b"\x01", left, right)
    return node


def empty_root() -> bytes:
    return DEFAULTS[DEPTH]


class SparseMerkle:
    def __init__(self) -> None:
        self.buckets: dict[int, dict[str, bytes]] = {}
        self.nodes: dict[tuple[int, int], bytes] = {}

    @property
    def root(self) -> bytes:
        return self.nodes.get((DEPTH, 0), DEFAULTS[DEPTH])

    def _node(self, level: int, index: int) -> bytes:
        return self.nodes.get((level, index), DEFAULTS[level])

    def get(self, key: str) -> bytes | None:
        return self.buckets.get(position(key), {}).get(key)

    def set(self, key: str, value: bytes | None) -> bytes:
        pos = position(key)
        bucket = self.buckets.setdefault(pos, {})
        if value is None:
            bucket.pop(key, None)
        else:
            bucket[key] = value
        if not bucket:
            del self.buckets[pos]
        self.nodes[(0, pos)] = leaf_hash(bucket)
        index = pos
        for level in range(DEPTH):
            left, right = (index & ~1), (index | 1)
            parent = _sha(b"\x01", self._node(level, left), self._node(level, right))
            index >>= 1
            self.nodes[(level + 1, index)] = parent
        return self.root

    def prove(self, key: str) -> dict[str, Any]:
        pos = position(key)
        siblings = [self._node(level, (pos >> level) ^ 1).hex() for level in range(DEPTH)]
        bucket = [[k, v.hex()] for k, v in sorted(self.buckets.get(pos, {}).items())]
        return {"bucket": bucket, "siblings": siblings}


def _unpack(proof: dict[str, Any]) -> tuple[dict[str, bytes], list[bytes]]:
    try:
        bucket = {k: bytes.fromhex(v) for k, v in proof["bucket"]}
        siblings = [bytes.fromhex(s) for s in proof["siblings"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofError("malformed proof") from exc
    if len(siblings) != DEPTH:
        raise ProofError("wrong proof length")
    return bucket, siblings

def recompute(key: str, proof: dict[str, Any]) -> tuple[bytes, bytes]:
    bucket, siblings = _unpack(proof)
    leaf = leaf_hash(bucket)
    return leaf, fold(leaf, position(key), siblings)


def verify(root: bytes, key: str, proof: dict[str, Any]) -> bytes | None:
    bucket, siblings = _unpack(proof)
    if any(position(k) != position(key) for k in bucket):
        raise ProofError("bucket does not belong to key position")
    if fold(leaf_hash(bucket), position(key), siblings) != root:
        raise ProofError("proof does not match root")
    return bucket.get(key)


def updated_root(root: bytes, key: str, value: bytes | None, proof: dict[str, Any]) -> bytes:
    verify(root, key, proof)
    bucket, siblings = _unpack(proof)
    if value is None:
        bucket.pop(key, None)
    else:
        bucket[key] = value
    return fold(leaf_hash(bucket), position(key), siblings)