from pathlib import Path
from bounty_hive.audit_log import AuditLog


def test_audit_log_chain_ok(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("a", "alice", {"x": 1})
    log.append("b", "alice", {"y": 2})
    ok, msg = log.verify()
    assert ok, msg
