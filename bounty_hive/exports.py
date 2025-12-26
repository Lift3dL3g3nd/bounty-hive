from __future__ import annotations

import json
from pathlib import Path

from .cache import PolicyCache
from .models import Context
from .normalize import normalize_policy
from .pdf_export import write_pdf_report
from .reporting import render_report_md


def export_policy_artifact(
    cache: PolicyCache,
    program_url: str,
    out_path: Path,
    fmt: str,
    overrides_path: Path,
    actor: str,
    role: str,
) -> bool:
    pol, _ = normalize_policy(
        cache, program_url, max_scope_items=200, overrides_path=overrides_path, refresh=False
    )

    if fmt == "json":
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(pol.to_json(), indent=2, sort_keys=True), encoding="utf-8")
        return True

    if fmt == "md":
        ctx = Context(
            program_url=program_url,
            cache_dir=str(cache.cache_dir),
            dry_run=True,
            auto_approve=False,
            llm_suggest=False,
            now_utc=pol.fetched_at_utc,
            actor=actor,
            role=role,
            policy=pol,
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render_report_md(ctx), encoding="utf-8")
        return True

    if fmt == "pdf":
        lines: list[str] = []
        lines.append(f"Program URL: {pol.program_url}")
        lines.append(f"Platform: {pol.platform_hint}")
        lines.append(f"Title: {pol.program_title}")
        lines.append(f"Fetched UTC: {pol.fetched_at_utc}")
        lines.append(f"Actor: {actor} (role {role})")
        lines.append("")
        lines.append("In scope (first 30):")
        for t in pol.in_scope[:30]:
            lines.append(f"  [{t.type}] {t.value}")
        return write_pdf_report("Bounty Hive Policy Export", lines, out_path)

    return False
