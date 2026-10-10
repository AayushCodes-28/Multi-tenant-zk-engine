from __future__ import annotations

import hashlib
import json
import time
from typing import Any

GENESIS = "0" * 64


def _digest(previous: str, body: dict[str, Any]) -> str:
    return hashlib.sha256((previous + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, **fields: Any) -> dict[str, Any]:
        previous = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {"seq": len(self.entries), "ts": round(time.time(), 3), **fields}
        entry = {**body, "prev": previous, "hash": _digest(previous, body)}
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        return verify_entries(self.entries)


def verify_entries(entries: list[dict[str, Any]]) -> tuple[bool, int | None]:
    previous = GENESIS
    for position, entry in enumerate(entries):
        body = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
        if entry.get("prev") != previous or entry.get("seq") != position or _digest(previous, body) != entry.get("hash"):
            return False, position
        previous = entry["hash"]
    return True, None