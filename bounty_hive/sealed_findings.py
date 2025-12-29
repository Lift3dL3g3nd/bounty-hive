from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .audit_log import AuditLog
from .models import Context


@dataclass(frozen=True)
class SealedFindingMeta:
    finding_id: str
    created_utc: str
    actor: str
    role: str
    policy_fingerprint: str


def _random_key() -> bytes:
    return os.urandom(32)  # AES-256


def seal_finding(
    *,
    finding_id: str,
    sealed_payload: dict[str, Any],
    ctx: Context,
    out_dir: Path,
    audit: AuditLog,
) -> SealedFindingMeta:
    """
    Encrypt sensitive AI reasoning and store it sealed.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # Serialize
    plaintext = json.dumps(sealed_payload, sort_keys=True).encode("utf-8")

    # Encrypt
    dek = _random_key()
    aes = AESGCM(dek)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    sealed_path = out_dir / f"{finding_id}.sealed"
    key_path = out_dir / f"{finding_id}.key"

    sealed_path.write_bytes(nonce + ciphertext)
    key_path.write_bytes(dek)  # TEMPORARY (Step 3 replaces this with vault wrapping)

    meta = SealedFindingMeta(
        finding_id=finding_id,
        created_utc=ctx.now_utc,
        actor=ctx.actor,
        role=ctx.role,
        policy_fingerprint=ctx.policy.raw_text_fingerprint if ctx.policy else "",
    )

    meta_path = out_dir / f"{finding_id}.meta.json"
    meta_path.write_text(json.dumps(meta.__dict__, indent=2), encoding="utf-8")

    audit.append(
        event="sealed_finding_created",
        actor=ctx.actor,
        details={
            "finding_id": finding_id,
            "policy_fingerprint": meta.policy_fingerprint,
        },
    )

    return meta
