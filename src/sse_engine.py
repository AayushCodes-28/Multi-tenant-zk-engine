"""Server-side opaque inverted index for blind exact-token search."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping


def _validate_trapdoor(value: str) -> None:
    if len(value) != 64:
        raise ValueError("trapdoor must be a SHA-256 hexadecimal digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("trapdoor must be hexadecimal") from exc


@dataclass(slots=True)
class EncryptedInvertedIndex:
    """A per-tenant mapping from opaque trapdoors to document identifiers."""

    tenant_id: str
    _postings: dict[str, set[str]] = field(default_factory=dict)

    def add_document(self, document_id: str, trapdoors: Iterable[str]) -> None:
        if not document_id:
            raise ValueError("document_id must not be empty")
        for trapdoor in set(trapdoors):
            _validate_trapdoor(trapdoor)
            self._postings.setdefault(trapdoor, set()).add(document_id)

    def remove_document(self, document_id: str) -> None:
        for trapdoor in list(self._postings):
            self._postings[trapdoor].discard(document_id)
            if not self._postings[trapdoor]:
                del self._postings[trapdoor]

    def search(self, trapdoor: str) -> tuple[str, ...]:
        """Match an opaque trapdoor without receiving a plaintext term."""
        _validate_trapdoor(trapdoor)
        return tuple(sorted(self._postings.get(trapdoor, set())))

    @property
    def term_count(self) -> int:
        return len(self._postings)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": 1,
            "tenant_id": self.tenant_id,
            "postings": {key: sorted(value) for key, value in sorted(self._postings.items())},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "EncryptedInvertedIndex":
        if data.get("version") != 1 or not isinstance(data.get("tenant_id"), str):
            raise ValueError("unsupported encrypted index format")
        postings = data.get("postings")
        if not isinstance(postings, dict):
            raise ValueError("postings must be an object")
        index = cls(str(data["tenant_id"]))
        for trapdoor, document_ids in postings.items():
            if not isinstance(trapdoor, str) or not isinstance(document_ids, list):
                raise ValueError("malformed postings entry")
            index.add_document_batch(trapdoor, document_ids)
        return index

    def add_document_batch(self, trapdoor: str, document_ids: Iterable[object]) -> None:
        _validate_trapdoor(trapdoor)
        converted = set()
        for document_id in document_ids:
            if not isinstance(document_id, str) or not document_id:
                raise ValueError("document IDs must be non-empty strings")
            converted.add(document_id)
        self._postings[trapdoor] = converted

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "EncryptedInvertedIndex":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

