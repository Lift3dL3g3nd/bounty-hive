from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import NormalizedPolicy, ScopeTarget


def load_overrides(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return list(d.get("overrides", []))
    except Exception:
        return []


def apply_overrides(pol: NormalizedPolicy, overrides: list[dict[str, Any]]) -> NormalizedPolicy:
    for ov in overrides:
        m = ov.get("match") or {}
        if str(m.get("program_url", "")).strip() != pol.program_url:
            continue
        s = ov.get("set") or {}

        hn = s.get("human_notes")
        if isinstance(hn, list):
            for x in hn:
                if isinstance(x, str) and x not in pol.human_notes:
                    pol.human_notes.append(x)

        for item in s.get("in_scope_add") or []:
            try:
                st = ScopeTarget(**item)
                st.source = st.source or "override"
                pol.in_scope.append(st)
            except Exception:
                continue

        for item in s.get("out_of_scope_add") or []:
            try:
                st = ScopeTarget(**item)
                st.source = st.source or "override"
                pol.out_of_scope.append(st)
            except Exception:
                continue

        pol.human_notes.append("Overrides applied from policy_overrides.json.")

    def dedupe(items: list[ScopeTarget]) -> list[ScopeTarget]:
        seen = set()
        out: list[ScopeTarget] = []
        for t in items:
            k = (t.type, (t.value or "").lower())
            if k in seen:
                continue
            seen.add(k)
            out.append(t)
        return out

    pol.in_scope = dedupe(pol.in_scope)
    pol.out_of_scope = dedupe(pol.out_of_scope)
    return pol
