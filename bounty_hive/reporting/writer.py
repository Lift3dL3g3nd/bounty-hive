"""
Unified report writer for bounty-hive.

Handles writing report artifacts to disk or stdout.
No knowledge of report format internals.
"""

import json
import sys
from typing import Any, Optional


def write_report(
    report: Any,
    output_path: Optional[str] = None,
    pretty: bool = True,
) -> None:
    """
    Write a report to disk or stdout.

    :param report: Serializable report object
    :param output_path: File path or None for stdout
    :param pretty: Pretty-print JSON
    """
    indent = 2 if pretty else None

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=indent)
            f.write("\n")
    else:
        json.dump(report, sys.stdout, indent=indent)
        sys.stdout.write("\n")
