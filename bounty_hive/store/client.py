
---

## Security & Data Handling Guarantees

The engine relies on the following guarantees from core:

- Hash-only export of sensitive artifacts
- No raw exploit material emitted or serialized
- Controlled lifecycle of audit artifacts
- Explicit destruction or sealing of unused artifacts

---

## Policy & Immutability Assumptions

The engine assumes:

- Policy snapshots are immutable once loaded
- Policy hashes uniquely identify enforcement state
- Runtime behavior cannot silently diverge from policy
- Violations trigger explicit halts or feasibility notices

---

## Change Discipline

Any change that breaks the expectations declared here is considered:

- a breaking change
- subject to versioning and review
- incompatible without engine updates

---

## Enforcement

These expectations are enforced through:

- invariant checks
- guard tests
- lifecycle validation
- audit logging

This document exists to declare intent, not replace enforcement.


"""
Pure store client interface.

This module is intentionally dependency-minimal and side-effect free.
It must remain import-pure to satisfy audit and policy constraints.
"""

from typing import Protocol, Any


class StoreClient(Protocol):
    def get(self, key: str) -> Any:
        ...

    def put(self, key: str, value: Any) -> None:
        ...
