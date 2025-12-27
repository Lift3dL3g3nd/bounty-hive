from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    title: str
    description: str
    file_path: str | None
    line: int | None
    evidence: dict[str, Any]
