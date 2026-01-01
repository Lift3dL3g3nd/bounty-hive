from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """
    Immutable, append-only audit record.

    The record_hash cryptographically commits to:
      - previous_hash
      - record metadata
      - payload_hash
    """

    record_id: str
    record_type: str
    subject_id: str
    schema_version: int
    actor: str
    timestamp_utc: str
    payload_hash: str
    previous_hash: Optional[str]
    record_hash: str

    @classmethod
    def create(
        cls,
        *,
        record_type: str,
        subject_id: str,
        schema_version: int,
        actor: str,
        payload_hash: str,
        previous_hash: Optional[str],
        timestamp_utc: Optional[str] = None,
    ) -> "AuditRecord":
        ts = timestamp_utc or _utc_now_iso()

        material = json.dumps(
            {
                "previous_hash": previous_hash,
                "record_type": record_type,
                "subject_id": subject_id,
                "schema_version": schema_version,
                "actor": actor,
                "timestamp_utc": ts,
                "payload_hash": payload_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        record_hash = _sha256_hex(material)

        return cls(
            record_id=record_hash[:16],
            record_type=record_type,
            subject_id=subject_id,
            schema_version=schema_version,
            actor=actor,
            timestamp_utc=ts,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )


__all__ = ["AuditRecord"]
