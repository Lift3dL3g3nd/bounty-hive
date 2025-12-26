from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditRecord:
    event: str
    actor: str
    timestamp_utc: str
    details: dict[str, Any]
    prev_hash: str
    hash: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _hash_payload(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class AuditLog:
    """Append-only JSONL log with hash chaining."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, actor: str, details: dict[str, Any] | None = None) -> AuditRecord:
        details = details or {}
        prev = self.last_hash()

        payload: dict[str, Any] = {
            "event": event,
            "actor": actor,
            "timestamp_utc": _utc_now(),
            "details": details,
            "prev_hash": prev,
        }
        payload["hash"] = _hash_payload(payload)

        rec = AuditRecord(**payload)  # type: ignore[arg-type]

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, sort_keys=True) + "\n")

        return rec

    def last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "GENESIS"

        last_line = self.path.read_text(encoding="utf-8").splitlines()[-1]
        try:
            return str(json.loads(last_line).get("hash", "GENESIS"))
        except Exception:
            return "GENESIS"

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "No log file."

        prev = "GENESIS"
        for idx, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            obj = json.loads(line)

            expected_prev = obj.get("prev_hash", "")
            if expected_prev != prev:
                return False, f"Chain break at line {idx}: prev_hash mismatch"

            h = obj.get("hash", "")
            payload = dict(obj)
            payload.pop("hash", None)
            payload["hash"] = _hash_payload(payload)

            if payload["hash"] != h:
                return False, f"Hash mismatch at line {idx}"

            prev = h

        return True, "OK"
