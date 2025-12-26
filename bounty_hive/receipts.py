from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass(frozen=True)
class ScopeReceipt:
    schema: str
    program_url: str
    actor: str
    role: str
    justification: str
    confirmed_utc: str
    policy_fingerprint: str
    in_scope_count: int
    out_of_scope_count: int
    signature_b64: str

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "program_url": self.program_url,
            "actor": self.actor,
            "role": self.role,
            "justification": self.justification,
            "confirmed_utc": self.confirmed_utc,
            "policy_fingerprint": self.policy_fingerprint,
            "in_scope_count": self.in_scope_count,
            "out_of_scope_count": self.out_of_scope_count,
            "signature_b64": self.signature_b64,
        }


def generate_keypair(key_dir: Path) -> tuple[Path, Path]:
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / "scope_receipt_ed25519.pem"
    pub_path = key_dir / "scope_receipt_ed25519.pub"

    if priv_path.exists() and pub_path.exists():
        return priv_path, pub_path

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)
    return priv_path, pub_path


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def sign_scope_receipt(
    receipts_dir: Path,
    key_dir: Path,
    *,
    program_url: str,
    actor: str,
    role: str,
    justification: str,
    policy_fingerprint: str,
    in_scope_count: int,
    out_of_scope_count: int,
) -> Path:
    receipts_dir.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = generate_keypair(key_dir)
    priv = _load_private_key(priv_path)

    payload = {
        "schema": "scope_receipt/1",
        "program_url": program_url,
        "actor": actor,
        "role": role,
        "justification": justification,
        "confirmed_utc": _utc_now(),
        "policy_fingerprint": policy_fingerprint,
        "in_scope_count": in_scope_count,
        "out_of_scope_count": out_of_scope_count,
    }
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = priv.sign(msg)

    receipt = ScopeReceipt(
        schema=payload["schema"],
        program_url=payload["program_url"],
        actor=payload["actor"],
        role=payload["role"],
        justification=payload["justification"],
        confirmed_utc=payload["confirmed_utc"],
        policy_fingerprint=payload["policy_fingerprint"],
        in_scope_count=payload["in_scope_count"],
        out_of_scope_count=payload["out_of_scope_count"],
        signature_b64=_b64(sig),
    )

    out_path = (
        receipts_dir
        / f"scope_receipt_{receipt.confirmed_utc.replace(':', '').replace('-', '')}.json"
    )
    out_path.write_text(json.dumps(receipt.to_json(), indent=2, sort_keys=True), encoding="utf-8")

    (receipts_dir / "scope_receipt_ed25519.pub").write_bytes(pub_path.read_bytes())
    return out_path


def verify_scope_receipt(receipt_path: Path, pubkey_path: Path) -> tuple[bool, str]:
    pub = _load_public_key(pubkey_path)
    d = json.loads(receipt_path.read_text(encoding="utf-8"))
    sig = _unb64(d["signature_b64"])

    payload = dict(d)
    payload.pop("signature_b64", None)
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    try:
        pub.verify(sig, msg)
        return True, "OK"
    except Exception as e:
        return False, f"FAIL: {e}"
