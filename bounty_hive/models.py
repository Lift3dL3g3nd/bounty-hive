from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

TargetType = Literal[
    "domain",
    "wildcard_domain",
    "ip",
    "cidr",
    "url",
    "app",
    "contract",
    "explorer_url",
    "repo",
    "unknown",
]


@dataclass
class ScopeTarget:
    value: str
    type: TargetType = "unknown"
    source: str = "parsed"
    notes: str = ""


@dataclass
class PolicyAllowances:
    passive_dns: bool = True
    passive_whois: bool = True
    automated_testing_allowed: bool = False
    active_scanning_allowed: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "passive_dns": self.passive_dns,
            "passive_whois": self.passive_whois,
            "automated_testing_allowed": self.automated_testing_allowed,
            "active_scanning_allowed": self.active_scanning_allowed,
        }


@dataclass
class PolicyConstraints:
    prohibits_dos: bool = True
    prohibits_social_engineering: bool = True
    prohibits_bruteforce: bool = True
    prohibits_exploitation: bool = True

    prohibits_automated_scanning_language_detected: bool = False
    requires_rate_limiting: bool = True
    requires_safe_harbor_language_detected: bool = False
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "prohibits_dos": self.prohibits_dos,
            "prohibits_social_engineering": self.prohibits_social_engineering,
            "prohibits_bruteforce": self.prohibits_bruteforce,
            "prohibits_exploitation": self.prohibits_exploitation,
            "prohibits_automated_scanning_language_detected": self.prohibits_automated_scanning_language_detected,
            "requires_rate_limiting": self.requires_rate_limiting,
            "requires_safe_harbor_language_detected": self.requires_safe_harbor_language_detected,
            "notes": list(self.notes),
        }


@dataclass
class NormalizedPolicy:
    schema_version: str = "1.0"
    program_url: str = ""
    platform_hint: str = ""
    program_title: str = ""

    fetched_at_utc: str = ""
    adapter_used: str = "generic"
    source_html_cache_path: str = ""

    in_scope: list[ScopeTarget] = field(default_factory=list)
    out_of_scope: list[ScopeTarget] = field(default_factory=list)

    rules_excerpt: str = ""
    raw_text_fingerprint: str = ""

    allowances: PolicyAllowances = field(default_factory=PolicyAllowances)
    constraints: PolicyConstraints = field(default_factory=PolicyConstraints)

    requires_human_scope_confirmation: bool = True
    human_notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "program_url": self.program_url,
            "platform_hint": self.platform_hint,
            "program_title": self.program_title,
            "fetched_at_utc": self.fetched_at_utc,
            "adapter_used": self.adapter_used,
            "source_html_cache_path": self.source_html_cache_path,
            "in_scope": [vars(x) for x in self.in_scope],
            "out_of_scope": [vars(x) for x in self.out_of_scope],
            "rules_excerpt": self.rules_excerpt,
            "raw_text_fingerprint": self.raw_text_fingerprint,
            "allowances": self.allowances.to_json(),
            "constraints": self.constraints.to_json(),
            "requires_human_scope_confirmation": self.requires_human_scope_confirmation,
            "human_notes": list(self.human_notes),
        }

    @staticmethod
    def from_json(d: dict[str, Any]) -> "NormalizedPolicy":
        pol = NormalizedPolicy()
        pol.schema_version = str(d.get("schema_version", "1.0"))
        pol.program_url = str(d.get("program_url", ""))
        pol.platform_hint = str(d.get("platform_hint", ""))
        pol.program_title = str(d.get("program_title", ""))
        pol.fetched_at_utc = str(d.get("fetched_at_utc", ""))
        pol.adapter_used = str(d.get("adapter_used", "generic"))
        pol.source_html_cache_path = str(d.get("source_html_cache_path", ""))
        pol.rules_excerpt = str(d.get("rules_excerpt", ""))
        pol.raw_text_fingerprint = str(d.get("raw_text_fingerprint", ""))
        pol.requires_human_scope_confirmation = bool(
            d.get("requires_human_scope_confirmation", True)
        )
        pol.human_notes = list(d.get("human_notes", []))
        pol.in_scope = [ScopeTarget(**x) for x in d.get("in_scope", [])]
        pol.out_of_scope = [ScopeTarget(**x) for x in d.get("out_of_scope", [])]
        return pol


@dataclass
class Action:
    name: str
    description: str
    category: Literal["policy_fetch", "planning", "passive_intel", "reporting"] = "planning"
    requires_approval: bool = True
    target: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Context:
    program_url: str
    cache_dir: str
    dry_run: bool
    auto_approve: bool
    llm_suggest: bool
    now_utc: str

    actor: str = "unknown"
    role: str = "viewer"

    policy: Optional[NormalizedPolicy] = None
    plan: list[Action] = field(default_factory=list)
    passive_results: dict[str, Any] = field(default_factory=dict)
    human_notes: list[str] = field(default_factory=list)
    llm_suggestions: list[str] = field(default_factory=list)
