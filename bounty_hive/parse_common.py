from __future__ import annotations

import re

from bs4 import BeautifulSoup

from .models import ScopeTarget

_DOMAIN_RE = re.compile(r"(?i)^(?:\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$")
_URL_RE = re.compile(r"(?i)^https?://")
_EVM_ADDR_RE = re.compile(r"(?i)^0x[a-f0-9]{40}$")


def soup_text(html: str) -> tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.text.strip() if soup.title and soup.title.text else ""
    text = soup.get_text("\n", strip=True)
    return title, text


def classify_target(raw: str, source: str = "parsed") -> ScopeTarget:
    s = (raw or "").strip().lstrip("-•* ").strip()
    if _URL_RE.search(s):
        return ScopeTarget(value=s, type="url", source=source)
    if _EVM_ADDR_RE.match(s):
        return ScopeTarget(value=s, type="contract", source=source)
    if _DOMAIN_RE.match(s):
        if s.startswith("*."):
            return ScopeTarget(value=s, type="wildcard_domain", source=source)
        return ScopeTarget(value=s, type="domain", source=source)
    return ScopeTarget(value=s, type="unknown", source=source)


def find_domains_loose(text: str) -> list[str]:
    token_re = re.compile(r"(?i)(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}")
    return sorted(set(token_re.findall(text or "")))


def extract_rules_excerpt(text: str, limit_lines: int = 120) -> str:
    keys = [
        "rules",
        "policy",
        "scope",
        "out of scope",
        "in scope",
        "safe harbor",
        "automated",
        "rate limit",
    ]
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    out: list[str] = []
    for ln in lines:
        low = ln.lower()
        if any(k in low for k in keys):
            out.append(ln)
    return "\n".join(out[:limit_lines])


def detect_constraints(text: str) -> dict[str, bool]:
    t = (text or "").lower()
    return {
        "no_automated_scanning_language": any(
            k in t for k in ["no automated", "do not scan", "no scanning", "do not use automated"]
        ),
        "safe_harbor_language": "safe harbor" in t or "safe-harbor" in t,
    }
