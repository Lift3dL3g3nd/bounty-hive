from __future__ import annotations

from ..fetch import fingerprint_text
from ..models import NormalizedPolicy, ScopeTarget
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
        title, text = soup_text(html)
        rules = extract_rules_excerpt(text)
        det = detect_constraints(text)

        pol = NormalizedPolicy(
            program_url=url,
            platform_hint=self._hint(url),
            program_title=title,
            fetched_at_utc=fetched_at_utc,
            adapter_used=self.name,
            source_html_cache_path=html_cache_path,
        )

        pol.rules_excerpt = rules
        pol.raw_text_fingerprint = fingerprint_text(text)

        domains = find_domains_loose(text)
        scope: list[ScopeTarget] = []

        for d in domains:
            if d.startswith("*."):
                scope.append(
                    ScopeTarget(
                        value=d,
                        type="wildcard_domain",
                        source="parsed",
                    )
                )
            else:
                scope.append(classify_target(d, "parsed"))

        pol.in_scope = scope[:250]

        pol.constraints.prohibits_automated_scanning_language_detected = bool(
            det.get("no_automated_scanning_language")
        )
        pol.constraints.requires_safe_harbor_language_detected = bool(
            det.get("safe_harbor_language")
        )

        pol.allowances.automated_testing_allowed = not det.get(
            "no_automated_scanning_language"
        )
        pol.allowances.active_scanning_allowed = False
        pol.requires_human_scope_confirmation = True

        return pol

    def _hint(self, url: str) -> str:
        u = (url or "").lower()
        if "hackerone.com" in u:
            return "hackerone"
        if "bugcrowd.com" in u:
            return "bugcrowd"
        if "yeswehack.com" in u:
            return "yeswehack"
        return "private"
