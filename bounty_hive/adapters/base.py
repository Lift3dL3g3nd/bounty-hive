from __future__ import annotations

from typing import Protocol


class PolicyAdapter(Protocol):
    name: str

    def supports(self, url: str) -> bool: ...
    def normalize(self, url: str, html: str, fetched_at_utc: str, html_cache_path: str) -> NormalizedPolicy: ...


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: list[PolicyAdapter] = []

    def register(self, adapter: PolicyAdapter) -> None:
        self._adapters.append(adapter)

    def pick(self, url: str) -> PolicyAdapter | None:
        for a in self._adapters:
            if a.supports(url):
                return a
        return None
