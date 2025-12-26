from __future__ import annotations

import json

from .models import Context


def render_report_md(ctx: Context) -> str:
    pol = ctx.policy
    lines: list[str] = []
    lines.append("# Compliance Report (Enterprise)")
    lines.append("")
    lines.append(f"- Generated (UTC): `{ctx.now_utc}`")
    lines.append(f"- Program URL: `{ctx.program_url}`")
    lines.append(f"- Actor: `{ctx.actor}` (role `{ctx.role}`)")
    lines.append("")
    lines.append("## What this tool did")
    lines.append("- Parsed public policy page")
    lines.append("- Normalized scope/rules into schema")
    lines.append("- (Optional) Passive DNS/WHOIS only if approved and scope-confirmed")
    lines.append("")
    lines.append("## What this tool did NOT do")
    lines.append("- No scanning, exploitation, brute force, DoS, or social engineering")
    lines.append("")

    if pol:
        lines.append("## Normalized policy")
        lines.append(f"- platform_hint: `{pol.platform_hint}`")
        lines.append(f"- program_title: `{pol.program_title}`")
        lines.append(f"- fetched_at_utc: `{pol.fetched_at_utc}`")
        lines.append(f"- fingerprint: `{pol.raw_text_fingerprint}`")
        lines.append("")
        lines.append("### Scope (confirm manually)")
        lines.append("#### In scope")
        for st in pol.in_scope[:250]:
            lines.append(f"- `{st.value}` *(type: {st.type}, source: {st.source})*")
        lines.append("")
        lines.append("### Rules excerpt")
        if (pol.rules_excerpt or "").strip():
            lines.append("```")
            lines.append(pol.rules_excerpt.strip()[:9000])
            lines.append("```")
        lines.append("")

    if ctx.llm_suggestions:
        lines.append("## LLM suggestions (read-only, guarded)")
        for s in ctx.llm_suggestions:
            lines.append("```")
            lines.append(s[:9000])
            lines.append("```")
        lines.append("")

    lines.append("## Plan")
    for i, a in enumerate(ctx.plan, start=1):
        appr = "YES" if a.requires_approval else "NO"
        tgt = f" target=`{a.target}`" if a.target else ""
        lines.append(f"{i}. **{a.name}** — {a.description} *(approval: {appr})*{tgt}")
    lines.append("")
    lines.append("## Passive results (if approved)")
    if ctx.passive_results:
        for k, v in ctx.passive_results.items():
            lines.append(f"### {k}")
            lines.append("```json")
            lines.append(json.dumps(v, indent=2, sort_keys=True)[:20000])
            lines.append("```")
            lines.append("")
    else:
        lines.append("- *(none executed)*")
        lines.append("")
    return "\n".join(lines)


def render_report_json(ctx: Context) -> str:
    d = {
        "generated_utc": ctx.now_utc,
        "program_url": ctx.program_url,
        "actor": ctx.actor,
        "role": ctx.role,
        "policy": ctx.policy.to_json() if ctx.policy else None,
        "plan": [a.__dict__ for a in ctx.plan],
        "passive_results": ctx.passive_results,
        "human_notes": ctx.human_notes,
        "llm_suggestions": ctx.llm_suggestions,
    }
    return json.dumps(d, indent=2, sort_keys=True)
