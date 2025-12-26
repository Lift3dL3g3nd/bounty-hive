from pathlib import Path
from bounty_hive.receipts import sign_scope_receipt, verify_scope_receipt


def test_receipt_sign_and_verify(tmp_path: Path):
    receipts_dir = tmp_path / "receipts"
    key_dir = tmp_path / "keys"
    receipt = sign_scope_receipt(
        receipts_dir=receipts_dir,
        key_dir=key_dir,
        program_url="https://example.local/policy",
        actor="alice",
        role="lead",
        justification="SEC-2411",
        policy_fingerprint="deadbeef",
        in_scope_count=2,
        out_of_scope_count=0,
    )
    pub = receipts_dir / "scope_receipt_ed25519.pub"
    ok, msg = verify_scope_receipt(receipt, pub)
    assert ok, msg
