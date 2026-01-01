from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from . import audit_chain


class AuditStore:
    """
    Append-only JSON audit log.

    Each record is stored as a dict derived from AuditRecord.
    This store NEVER mutates or reorders records.
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def _load(self) -> list[dict[str, Any]]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, records: list[dict[str, Any]]) -> None:
        self.path.write_text(
            json.dumps(records, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def last_hash(self) -> Optional[str]:
        records = self._load()
        if not records:
            return None
        return records[-1]["record_hash"]

    def append(self, record: audit_chain.AuditRecord) -> None:
        records = self._load()
        records.append(record.__dict__)
        self._save(records)
