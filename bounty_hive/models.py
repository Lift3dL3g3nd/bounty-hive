from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
# ----------------------------------------------------------------------
# Scope models
# ----------------------------------------------------------------------


@dataclass
class ScopeTarget:
    """
    Represents a single scope entry.

    Examples:
      - example.com
      - *.example.com
      - 192.168.0.0/24
      - https://example.com/api
      - github.com/org/repo
    """

    value: str
    target_type: str  # domain, wildcard, ip, cidr, url, repo


# ----------------------------------------------------------------------
# Core domain models
# ----------------------------------------------------------------------


@dataclass
class Action:
    tool: str
    target: str
    category: str


@dataclass
class NormalizedPolicy:
    raw_text_fingerprint: str
    in_scope: List[str]
    out_of_scope: List[str]
    requires_human_scope_confirmation: bool = True


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
# AI Analysis Models (REQUIRED)
# ----------------------------------------------------------------------


@dataclass
class PublicFinding:
    """
    Report-safe AI finding.

    This object may be rendered into reports and the GUI.
    It MUST NOT contain exploit steps, payloads, or bypass instructions.
    """

    finding_id: str
    title: str
    category: str
    severity: str
    confidence: float
    description: str
    mitigation: str
    evidence_refs: List[str]


@dataclass
class SealedFindingRef:
    """
    Reference to encrypted AI reasoning stored on disk.
    """

    finding_id: str
    sealed_path: str
    meta_path: str
