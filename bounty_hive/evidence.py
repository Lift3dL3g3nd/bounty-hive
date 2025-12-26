from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .models import Context


def write_evidence_index(project_root: Path, ctx: Context, out_path: Path | None = None) -> Path:
    project_root = project_root.resolve()
    if out_path is None:
        out_path = project_root / "docs" / "EVIDENCE_INDEX.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    lines: list[str] = []
    lines.append("# Evidence Index")
    lines.append("")
    lines.append(f"- Generated UTC: `{now}`")
    lines.append(f"- Tool run actor: `{ctx.actor}`")
    lines.append(f"- Role: `{ctx.role}`")
    lines.append(f"- Program URL: `{ctx.program_url}`")
    lines.append("")
    lines.append("## What this tool did")
    lines.append("- Parsed public policy page(s)")
    lines.append("- Normalized scope and rule text into a structured schema")
    lines.append("- Produced compliance/evidence artifacts")
    lines.append("- (Optional) Performed passive DNS/WHOIS only if scope-confirmed and approved")
    lines.append("")
    lines.append("## What this tool did NOT do")
    lines.append("- No scanning, exploitation, brute force, DoS, or social engineering")
    lines.append("- No credential testing or authentication attacks")
    lines.append("")
    lines.append("## Scope confirmation")
    if ctx.policy:
        lines.append(
            f"- requires_human_scope_confirmation: `{ctx.policy.requires_human_scope_confirmation}`"
        )
        if ctx.policy.human_notes:
            lines.append("- human_notes:")
            for n in ctx.policy.human_notes[:50]:
                lines.append(f"  - {n}")
    else:
        lines.append("- No policy loaded.")
    lines.append("")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
