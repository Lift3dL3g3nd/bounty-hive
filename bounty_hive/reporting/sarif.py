"""
SARIF report generation for bounty-hive.

This module converts normalized Finding objects into
SARIF 2.1.0 compliant output suitable for CI systems,
code scanning tools, and security platforms.
"""

from typing import Iterable, Dict, Any
import hashlib
from datetime import datetime, timezone
from collections import OrderedDict

# Map internal severities to SARIF levels
SARIF_LEVEL_MAP = {
    "LOW": "note",
    "MEDIUM": "warning",
    "HIGH": "error",
    "CRITICAL": "error",
}
TOOL_NAME = "bounty-hive"
TOOL_VERSION = "0.1.0"  # keep in sync with pyproject.toml
TOOL_URI = "https://github.com/your-org/bounty-hive"


def _sarif_level(severity: str) -> str:
    return SARIF_LEVEL_MAP.get(severity.upper(), "warning")


def _location_fingerprint(path: str, line: int | None) -> str:
    h = hashlib.sha256()
    h.update((path or "").encode())
    if line is not None:
        h.update(str(line).encode())
    return h.hexdigest()


def findings_to_sarif(findings: Iterable[Any]) -> Dict[str, Any]:
    """
    Convert normalized findings into a SARIF 2.1.0 document.

    Expected Finding attributes:
      - rule_id
      - severity
      - tool
      - file_path (optional)
      - line (optional)
    """

    rules: OrderedDict[str, Dict[str, Any]] = OrderedDict()
    results = []

    for f in findings:
        # ---- Rules (unique per rule_id) ----
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.rule_id},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
            }

        # ---- Location ----
        location: Dict[str, Any] = {
            "physicalLocation": {"artifactLocation": {"uri": f.file_path or "N/A"}}
        }

        if getattr(f, "line", None) is not None:
            location["physicalLocation"]["region"] = {"startLine": int(f.line)}

        # ---- Result ----
        fingerprint = _location_fingerprint(
            f.file_path,
            getattr(f, "line", None),
        )

        results.append(
            {
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f"{f.tool}: {f.rule_id}"},
                "locations": [location],
                "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            }
        )

    # ---- Final SARIF Document ----
    # ---- Final SARIF Document ----
    # ---- Deterministic ordering for CI / diff stability ----
    sorted_rules = sorted(rules.values(), key=lambda r: r["id"])

    results = sorted(
        results,
        key=lambda r: (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        ),
    )

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": sorted_rules,
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
            }
        ],
    }
