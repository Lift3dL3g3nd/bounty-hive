from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .models import NormalizedPolicy


class PolicyCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.html_dir = cache_dir / "html"
        self.pol_dir = cache_dir / "policies"
        self.html_dir.mkdir(parents=True, exist_ok=True)
        self.pol_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def url_key(url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]

    def policy_path(self, url: str) -> Path:
        return self.pol_dir / f"{self.url_key(url)}.json"

    def html_path(self, url: str) -> Path:
        return self.html_dir / f"{self.url_key(url)}.html"

    def load_by_url(self, url: str) -> Optional[NormalizedPolicy]:
        p = self.policy_path(url)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return NormalizedPolicy(**data)
        except Exception:
            return None

    def save(self, policy: NormalizedPolicy, program_url: str) -> Path:
        p = self.policy_path(program_url)
        p.write_text(
            json.dumps(asdict(policy), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return p
