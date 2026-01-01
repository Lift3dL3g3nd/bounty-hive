from __future__ import annotations

from ..fetch import fingerprint_text
from ..models import NormalizedPolicy, ScopeTarget, PolicyConstraints
from ..parse_common import (
    classify_target,
    detect_constraints,
    extract_rules_excerpt,
    find_domains_loose,
    soup_text,
)


class GenericAdapter:
    name = "generic"

    def supports(self, url: str) -> bool:
        return True

    def normalize(
        self,
        url: str,
        html: str,
        fetched_at_utc: str,
        html_cache_path: str,
    ) -> NormalizedPolicy:
        # --- Parse text ---
        title, text = soup_text(html)
        rules = extract_rules_excerpt(text)

        # --- Constraint detection (AI + deterministic fallback) ---
        detected = detect_constraints(text) or {}
        low = text.lower()

        prohibits_automated = (
            detected.get("prohibits_automated_scanning_language_detected")
            or "no scanning" in low
            or "no automated" in low
            or "no automated tools" in low
        )

        constraints = PolicyConstraints(
            prohibits_automated_scanning_language_detected=bool(prohibits_automated),
            prohibits_exploitation_language_detected=bool(
                detected.get("prohibits_exploitation_language_detected")
            ),
            requires_safe_harbor_language_detected=bool(
                detected.get("safe_harbor_language_detected") or "safe harbor" in low
            ),
        )

        # --- Scope extraction ---
        domains = find_domains_loose(text)
        scope: list[ScopeTarget] = []

        for d in domains:
            if d.startswith("*."):
                scope.append(ScopeTarget(d, "wildcard_domain"))
            else:
                scope.append(classify_target(d, "parsed"))

        # --- Final normalized policy ---
        return NormalizedPolicy(
            program_url=url,
            platform_hint=self._hint(url),
            program_title=title.strip() if title else "Example Program Policy",
            fetched_at_utc=fetched_at_utc,
            adapter_used=self.name,
            source_html_cache_path=html_cache_path,
            raw_text_fingerprint=fingerprint_text(text),
            rules_excerpt=rules,
            in_scope=scope[:250],
            out_of_scope=[],
            constraints=constraints,
            requires_human_scope_confirmation=True,
        )

    def _hint(self, url: str) -> str:
        u = (url or "").lower()
        if "hackerone.com" in u:
            return "hackerone"
        if "bugcrowd.com" in u:
            return "bugcrowd"
        if "yeswehack.com" in u:
            return "yeswehack"
        return "private"
