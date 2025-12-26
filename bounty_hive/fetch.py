from __future__ import annotations

import hashlib
from pathlib import Path

import requests


def fetch_html(url: str, html_path: Path, timeout_s: int = 45) -> str:
    if html_path.exists() and html_path.stat().st_size > 300:
        return html_path.read_text(encoding="utf-8", errors="replace")
    r = requests.get(
        url, timeout=timeout_s, headers={"User-Agent": "BountyHive/Enterprise (passive-only)"}
    )
    r.raise_for_status()
    html = r.text
    html_path.write_text(html, encoding="utf-8")
    return html


def fingerprint_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()
