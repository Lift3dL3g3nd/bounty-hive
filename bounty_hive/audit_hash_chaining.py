from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    record_id: str
    record_type: str
    subject_id: str
    schema_version: int
    actor: str
    timestamp_utc: str
    payload_hash: str
    previous_hash: Optional[str]
    record_hash: str

    @staticmethod
    def create(
        *,
        record_type: str,
        subject_id: str,
        schema_version: int,
        actor: str,
        payload_hash: str,
        previous_hash: Optional[str],
    ) -> "AuditRecord":
        timestamp = utc_now()

        material = json.dumps(
            {
                "previous_hash": previous_hash,
                "record_type": record_type,
                "subject_id": subject_id,
                "schema_version": schema_version,
                "actor": actor,
                "timestamp_utc": timestamp,
                "payload_hash": payload_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        record_hash = sha256_hex(material)

        return AuditRecord(
            record_id=record_hash[:16],
            record_type=record_type,
            subject_id=subject_id,
            schema_version=schema_version,
            actor=actor,
            timestamp_utc=timestamp,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )
