from __future__ import annotations

import json
from pathlib import Path

from bounty_hive.audit_chain import AuditRecord
from bounty_hive.audit_store import AuditStore
from bounty_hive.audit_verify import verify_audit_file


def test_verify_audit_chain_ok(tmp_path: Path):
    audit_path = tmp_path / "audit_chain.json"
    store = AuditStore(audit_path)

    r1 = AuditRecord.create(
        record_type="unit",
        subject_id="a",
        schema_version=1,
        actor="tester",
        payload_hash="x",
        previous_hash=None,
        timestamp_utc="2026-01-01T00:00:00+00:00",
    )
    store.append(r1)

    r2 = AuditRecord.create(
        record_type="unit",
        subject_id="b",
        schema_version=1,
        actor="tester",
        payload_hash="y",
        previous_hash=store.last_hash(),
        timestamp_utc="2026-01-01T00:00:01+00:00",
    )
    store.append(r2)

    res = verify_audit_file(audit_path)
    assert res.ok is True
    assert res.count == 2
    assert res.issues == []


def test_verify_detects_tamper_payload_hash(tmp_path: Path):
    audit_path = tmp_path / "audit_chain.json"
    store = AuditStore(audit_path)

    r1 = AuditRecord.create(
        record_type="unit",
        subject_id="a",
        schema_version=1,
        actor="tester",
        payload_hash="x",
        previous_hash=None,
        timestamp_utc="2026-01-01T00:00:00+00:00",
    )
    store.append(r1)

    r2 = AuditRecord.create(
        record_type="unit",
        subject_id="b",
        schema_version=1,
        actor="tester",
        payload_hash="y",
        previous_hash=store.last_hash(),
        timestamp_utc="2026-01-01T00:00:01+00:00",
    )
    store.append(r2)

    # Tamper: edit payload_hash in the stored JSON without updating record_hash
    data = json.loads(audit_path.read_text(encoding="utf-8"))
    data[1]["payload_hash"] = "TAMPERED"
    audit_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    res = verify_audit_file(audit_path)
    assert res.ok is False
    assert any("record_hash mismatch" in issue.reason for issue in res.issues)


def test_verify_detects_broken_previous_hash(tmp_path: Path):
    audit_path = tmp_path / "audit_chain.json"
    store = AuditStore(audit_path)

    r1 = AuditRecord.create(
        record_type="unit",
        subject_id="a",
        schema_version=1,
        actor="tester",
        payload_hash="x",
        previous_hash=None,
        timestamp_utc="2026-01-01T00:00:00+00:00",
    )
    store.append(r1)

    r2 = AuditRecord.create(
        record_type="unit",
        subject_id="b",
        schema_version=1,
        actor="tester",
        payload_hash="y",
        previous_hash=store.last_hash(),
        timestamp_utc="2026-01-01T00:00:01+00:00",
    )
    store.append(r2)

    # Break the chain: previous_hash doesn't match r1.record_hash
    data = json.loads(audit_path.read_text(encoding="utf-8"))
    data[1]["previous_hash"] = "0" * 64
    audit_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    res = verify_audit_file(audit_path)
    assert res.ok is False
    assert any("previous_hash mismatch" in issue.reason for issue in res.issues)
