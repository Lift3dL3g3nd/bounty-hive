from __future__ import annotations

from typing import Dict, Any

from bounty_hive.validation.disclosure_package import validate_disclosure_package


def ingest_engine_disclosure(pkg: Dict[str, Any]) -> None:
    """
    CORE TRUST BOUNDARY

    This is the ONLY function allowed to accept Engine disclosure packages.
    Validation MUST occur before any access, storage, or state changes.
    """

    # 🔒 TRUST BOUNDARY — FIRST LINE, NO EXCEPTIONS
    validate_disclosure_package(pkg)

    # ----------------------------
    # From here down, data is trusted
    # ----------------------------

    package_id = pkg["package_id"]
    state = pkg["state"]

    # TODO (next steps):
    # - store metadata only (IDs, hashes, state)
    # - do NOT store artifact bodies
    # - do NOT advance lifecycle here (separate concern)
    # - emit audit receipt later

    # Placeholder to make intent explicit
    return None
