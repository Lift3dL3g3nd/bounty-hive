from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    title: str | None = None
    description: str | None = None
    file_path: str | None = None
    line: int | None = None
    evidence: dict[str, Any] | None = None
