from __future__ import annotations

from pathlib import Path

from .cache import PolicyCache
from .normalize import normalize_policy


def diff_policies(cache: PolicyCache, urls: list[str], refresh: bool, overrides_path: Path) -> str:
    if len(urls) < 2:
        return "Need at least two program URLs to diff."

    policies = []
    for u in urls:
        pol, _ = normalize_policy(
            cache, u, max_scope_items=250, overrides_path=overrides_path, refresh=refresh
        )
        policies.append(pol)

    lines: list[str] = []
    lines.append("POLICY DIFF (enterprise)")
    lines.append("=" * 72)
    lines.append("")
    for p in policies:
        lines.append(f"- {p.program_url} | platform={p.platform_hint} | title={p.program_title}")
    lines.append("")
    lines.append("IN-SCOPE (first 60 each)")
    lines.append("-" * 72)
    for p in policies:
        lines.append(f"## {p.program_url}")
        for t in p.in_scope[:60]:
            lines.append(f"- [{t.type}] {t.value}")
        lines.append("")
    return "\n".join(lines)
