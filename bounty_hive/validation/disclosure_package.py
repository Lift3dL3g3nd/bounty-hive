from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft202012Validator


def _schema_path() -> Path:
    """
    Locate the mirrored disclosure package schema in Core.
    """
    return (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "disclosure_package.schema.json"
    )


def _load_validator() -> Draft202012Validator:
    schema_path = _schema_path()
    if not schema_path.exists():
        raise RuntimeError(f"Disclosure schema missing in Core: {schema_path}")

    with schema_path.open("r", encoding="utf-8") as f:
        schema = json.load(f)

    return Draft202012Validator(schema)


def _canonical_sha256(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_disclosure_package(pkg: Dict[str, Any]) -> None:
    """
    CORE TRUST VERIFIER

    Enforces:
    - finalized-only packages
    - schema correctness
    - canonical hash integrity
    """

    if not isinstance(pkg, dict):
        raise ValueError("Disclosure package must be a dict")

    # ----------------------------
    # Finalization checks
    # ----------------------------
    if "package_id" not in pkg:
        raise ValueError("Missing package_id (not finalized)")

    if "_canonical_sha256" not in pkg:
        raise ValueError("Missing _canonical_sha256 (not finalized)")

    # ----------------------------
    # Schema validation
    # ----------------------------
    validator = _load_validator()

    schema_view = {
        k: v for k, v in pkg.items()
        if k != "_canonical_sha256"
    }

    validator.validate(schema_view)

    # ----------------------------
    # Canonical hash verification
    # ----------------------------
    expected = pkg["_canonical_sha256"]
    actual = _canonical_sha256(schema_view)

    if expected != actual:
        raise ValueError(
            "Canonical hash mismatch (package was modified or non-canonical)"
        )
