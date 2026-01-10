from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .schema import NORMALIZED_POLICY_SCHEMA_VERSION

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
    # --- Identity / provenance ---
    program_url: str
    platform_hint: str
    program_title: str
    fetched_at_utc: str
    adapter_used: str
    source_html_cache_path: str

    # --- Content ---
    raw_text_fingerprint: str
    rules_excerpt: str

    # --- Scope ---
    in_scope: List[ScopeTarget]
    out_of_scope: List[ScopeTarget]

    # --- Constraints ---
    constraints: PolicyConstraints

    # --- Governance ---
    requires_human_scope_confirmation: bool

    # --- Schema (keyword-only, defaulted, non-positional) ---
    schema_version: int = field(
        default=NORMALIZED_POLICY_SCHEMA_VERSION,
        kw_only=True,
    )


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


# ----------------------------------------------------------------------
# Findings (Visibility-Safe Models)
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class PublicFinding:
    """
    User-visible, redacted finding.
    MUST NOT contain exploit steps, payloads, or reproduction code.
    Safe for CLI output, SARIF export, and public repositories.
    """

    finding_id: str
    title: str
    severity: str
    summary: str
    affected_component: Optional[str] = None


@dataclass(frozen=True)
class SealedFindingRef:
    """
    Opaque reference to sealed / sensitive artifacts.
    Used for audit, custody, and entitlement checks only.
    """

    finding_id: str
    artifact_hash: str
