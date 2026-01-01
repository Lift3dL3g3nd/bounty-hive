from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


# ----------------------------------------------------------------------
# Scope
# ----------------------------------------------------------------------


@dataclass
class ScopeTarget:
    value: str
    target_type: str


# ----------------------------------------------------------------------
# Constraints
# ----------------------------------------------------------------------


@dataclass
class PolicyConstraints:
    prohibits_automated_scanning_language_detected: bool = False
    prohibits_exploitation_language_detected: bool = False
    requires_safe_harbor_language_detected: bool = False


# ----------------------------------------------------------------------
# Normalized Policy
# ----------------------------------------------------------------------


@dataclass
class NormalizedPolicy:
    # Identity / provenance
    program_url: str
    platform_hint: str
    program_title: str
    fetched_at_utc: str
    adapter_used: str
    source_html_cache_path: str

    # Content
    raw_text_fingerprint: str
    rules_excerpt: str

    # Scope
    in_scope: List[ScopeTarget]
    out_of_scope: List[ScopeTarget]

    # Constraints
    constraints: PolicyConstraints

    # Governance
    requires_human_scope_confirmation: bool


# ----------------------------------------------------------------------
# Execution Context
# ----------------------------------------------------------------------


@dataclass
class Context:
    program_url: str
    cache_dir: str
    dry_run: bool
    auto_approve: bool
    llm_suggest: bool
    now_utc: str
    actor: str
    role: str
    policy: Optional[NormalizedPolicy] = None
