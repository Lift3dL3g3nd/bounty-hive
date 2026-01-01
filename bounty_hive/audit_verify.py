from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class VerificationIssue:
    index: int
    record_id: str
    reason: str


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    count: int
    last_hash: Optional[str]
    issues: list[VerificationIssue]


def _compute_record_hash(record: dict[str, Any]) -> str:
    """
    Must match AuditRecord.create() hashing material exactly.
    """
    material = json.dumps(
        {
            "previous_hash": record.get("previous_hash"),
            "record_type": record["record_type"],
            "subject_id": record["subject_id"],
            "schema_version": record["schema_version"],
            "actor": record["actor"],
            "timestamp_utc": record["timestamp_utc"],
            "payload_hash": record["payload_hash"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_records(records: list[dict[str, Any]]) -> VerificationResult:
    issues: list[VerificationIssue] = []

    if not records:
        return VerificationResult(ok=True, count=0, last_hash=None, issues=[])

    prev_hash: Optional[str] = None

    for i, rec in enumerate(records):
        rec_id = str(rec.get("record_id", ""))

        # 1) previous_hash linkage
        expected_prev = prev_hash
        actual_prev = rec.get("previous_hash")
        if actual_prev != expected_prev:
            issues.append(
                VerificationIssue(
                    index=i,
                    record_id=rec_id,
                    reason=f"previous_hash mismatch: expected={expected_prev} actual={actual_prev}",
                )
            )

        # 2) record_hash correctness
        expected_hash = _compute_record_hash(rec)
        actual_hash = rec.get("record_hash")
        if actual_hash != expected_hash:
            issues.append(
                VerificationIssue(
                    index=i,
                    record_id=rec_id,
                    reason="record_hash mismatch (tampering or non-canonical write)",
                )
            )

        prev_hash = actual_hash if isinstance(actual_hash, str) else None

    last_hash = records[-1].get("record_hash")
    ok = len(issues) == 0
    return VerificationResult(ok=ok, count=len(records), last_hash=last_hash, issues=issues)


def verify_audit_file(path: Path) -> VerificationResult:
    if not path.exists():
        return VerificationResult(ok=True, count=0, last_hash=None, issues=[])

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return VerificationResult(
            ok=False,
            count=0,
            last_hash=None,
            issues=[
                VerificationIssue(index=-1, record_id="", reason="audit file is not a JSON list")
            ],
        )

    # Ensure dict-like entries
    records: list[dict[str, Any]] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            return VerificationResult(
                ok=False,
                count=0,
                last_hash=None,
                issues=[
                    VerificationIssue(index=i, record_id="", reason="non-dict record encountered")
                ],
            )
        records.append(item)

    return verify_records(records)
