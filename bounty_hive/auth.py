from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class User:
    username: str
    role: str  # viewer | analyst | lead | compliance | admin


PERMISSIONS: Final[dict[str, set[str]]] = {
    "viewer": {"read"},
    "analyst": {"read", "normalize"},
    "lead": {"read", "normalize", "confirm_scope"},
    "compliance": {"read", "export", "audit"},
    "admin": {"*"},
}


def can(user: User, action: str) -> bool:
    perms = PERMISSIONS.get(user.role, set())
    return "*" in perms or action in perms
