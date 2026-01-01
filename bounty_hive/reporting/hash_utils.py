# bounty_hive/reporting/hash_utils.py

import json
import hashlib
from typing import Dict, Any


def canonical_json(obj: Dict[str, Any]) -> bytes:
    """
    Produce a canonical JSON byte representation suitable for hashing.
    Deterministic across runs.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_canonical(obj: Dict[str, Any]) -> str:
    """
    Compute SHA-256 hash of canonical JSON.
    Returns hex digest.
    """
    return hashlib.sha256(canonical_json(obj)).hexdigest()
