from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class User:
    username: str
    role: str  # viewer | analyst | lead | compliance | admin


PERMISSIONS: Final[dict[str, set[str]]] = {
    "viewer": {"read"},
    "analyst": {"read", "normalize", "generate_sealed_findings"},
    "lead": {
        "read",
        "normalize",
        "confirm_scope",
        "generate_sealed_findings",
        "reveal_sealed_findings",
    },
    "compliance": {"read", "export", "audit"},
    "admin": {"*"},
}


def can(user: User, action: str) -> bool:
    perms = PERMISSIONS.get(user.role, set())
    return "*" in perms or action in perms
