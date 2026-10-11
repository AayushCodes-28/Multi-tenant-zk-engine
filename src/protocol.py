from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping

TRAPDOOR_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RECORD_FIELDS = ("id", "payload", "amount", "department", "classification")


def record_digest(record: Mapping[str, Any]) -> bytes:
    body = {name: record[name] for name in RECORD_FIELDS}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).digest()


def posting_digest(ids: Iterable[str]) -> bytes:
    return hashlib.sha256("\n".join(sorted(set(ids))).encode()).digest()