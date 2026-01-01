from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple
import json

from .audit_log import AuditLog
from .auth import User, can
from .findings import Finding
from .models import Context
from .passive_tools import (
    resolve_a_records,
    whois,
    run_bandit,
    normalize_bandit_findings,
)
from .ai_analysis import ai_analyze_findings


# ----------------------------------------------------------------------
# Orchestrator configuration
# ----------------------------------------------------------------------


@dataclass
class OrchestratorConfig:
    cache_dir: Path
    dry_run: bool = True
    auto_approve: bool = False


# ----------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------


class Orchestrator:
    """
    Passive-only orchestrator.

    Executes allowed passive tools, then (optionally) runs AI analysis
    if scope + RBAC permit.
    """

    def __init__(self, cfg: OrchestratorConfig, ctx: Context):
        self.cfg = cfg
        self.ctx = ctx
        self.audit = AuditLog(cfg.cache_dir / "audit.log.jsonl")

    def run(self) -> Tuple[List[Finding], list, list]:
        findings: List[Finding] = []

        # --------------------------------------------------
        # PASSIVE TOOLS (NO ATTACKS, NO ACTIVE SCANNING)
        # --------------------------------------------------
        try:
            if self.ctx.policy:
                targets = self.ctx.policy.in_scope
            else:
                targets = []

            # DNS + WHOIS are informational only
            for target in targets:
                resolve_a_records(target)
                whois(target)

            # Bandit scan
            bandit_out = run_bandit(Path.cwd(), self.cfg.cache_dir)
            with bandit_out.open("r", encoding="utf-8") as fh:
                data = json.load(fh)

            findings.extend(normalize_bandit_findings(data))

        except Exception as e:
            self.audit.append(
                "orchestrator_error",
                self.ctx.actor,
                {"error": str(e)},
            )
            raise

        # --------------------------------------------------
        # AI ANALYSIS (GUARDED)
        # --------------------------------------------------
        public_findings = []
        sealed_refs = []

        if self.ctx.policy and not self.ctx.policy.requires_human_scope_confirmation:
            user = User(username=self.ctx.actor, role=self.ctx.role)

            if can(user, "generate_sealed_findings"):
                public_findings, sealed_refs = ai_analyze_findings(
                    self.ctx,
                    findings,
                )
            else:
                self.audit.append(
                    "ai_analysis_skipped",
                    self.ctx.actor,
                    {"reason": "RBAC denied"},
                )
        else:
            self.audit.append(
                "ai_analysis_skipped",
                self.ctx.actor,
                {"reason": "scope not confirmed"},
            )

        return findings, public_findings, sealed_refs


# ----------------------------------------------------------------------
# Legacy helper (CLI compatibility)
# ----------------------------------------------------------------------


def scan_repo(path: Path, ctx: Context | None = None):
    """
    Compatibility wrapper used by cli.py.

    Keeps older CLI code working while using the new Orchestrator.
    """
    if ctx is None:
        return [], [], []

    cfg = OrchestratorConfig(cache_dir=Path(ctx.cache_dir))
    orch = Orchestrator(cfg, ctx)
    return orch.run()
