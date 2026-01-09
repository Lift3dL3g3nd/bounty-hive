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
