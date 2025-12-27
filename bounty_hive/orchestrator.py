from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .audit_log import AuditLog
from .auth import User, can
from .evidence import write_evidence_index
from .llm import LLMClient
from .models import Action, Context
from .passive_tools import resolve_a_records, whois, scan_python_repo
from .receipts import sign_scope_receipt
from .reporting import render_report_json, render_report_md
from .safety import SafetyGuard
from pathlib import Path
from .passive_tools import run_bandit, normalize_bandit_findings
from .audit_log import AuditLog
from pathlib import Path
from .reporting import write_scan_reports


@dataclass
class OrchestratorConfig:
    out_dir: Path
    dry_run: bool
    auto_approve: bool


class Orchestrator:
    def __init__(self, cfg: OrchestratorConfig, ctx: Context):
        self.cfg = cfg
        self.ctx = ctx
        self.console = Console()

        self.user = User(
            username=getattr(ctx, "actor", "unknown"),
            role=getattr(ctx, "role", "viewer"),
        )
        self.audit = AuditLog(Path(ctx.cache_dir) / "audit.log.jsonl")

    def run(self) -> None:
        self.audit.append(
            "orchestrator_start",
            self.user.username,
            {"role": self.user.role, "program_url": self.ctx.program_url},
        )
        self.console.print(f"[bold]Program:[/bold] {self.ctx.program_url}")

        if self.ctx.policy:
            self._display_policy_summary()

        if self.ctx.llm_suggest and self.ctx.policy:
            self._make_llm_suggestions()

        self._build_plan()
        self._human_confirm_scope_rbac_and_sign_receipt()

        guard = SafetyGuard(self.ctx.policy)
        self._execute_plan(guard)

        self._write_reports()
        self._write_evidence_index()

        self.audit.append(
            "orchestrator_end",
            self.user.username,
            {"role": self.user.role, "program_url": self.ctx.program_url},
        )

    def _build_plan(self) -> None:
        self.ctx.plan.append(
            Action(
                name="HumanReviewPolicy",
                description="Human reviews normalized policy and constraints.",
                category="planning",
                requires_approval=False,
            )
        )
        self.ctx.plan.append(
            Action(
                name="ConfirmScope",
                description="Confirm scope before any passive actions (RBAC gated).",
                category="planning",
                requires_approval=False,
            )
        )

        if self.ctx.policy:
            for st in self.ctx.policy.in_scope[:10]:
                if st.type in {"domain", "wildcard_domain"}:
                    target = st.value.replace("*.", "")
                    self.ctx.plan.append(
                        Action(
                            name="PassiveDNSResolve",
                            description="Resolve A/AAAA records (passive).",
                            category="passive_intel",
                            requires_approval=True,
                            target=target,
                            metadata={"tool": "resolve_a_records"},
                        )
                    )
                    self.ctx.plan.append(
                        Action(
                            name="PassiveWHOIS",
                            description="WHOIS lookup (passive).",
                            category="passive_intel",
                            requires_approval=True,
                            target=target,
                            metadata={"tool": "whois"},
                        )
                    )

        self.ctx.plan.append(
            Action(
                name="GenerateReport",
                description="Generate compliance report artifacts.",
                category="reporting",
                requires_approval=False,
            )
        )

    def _human_confirm_scope_rbac_and_sign_receipt(self) -> None:
        pol = self.ctx.policy
        if not pol:
            return

        self.console.print("\n[bold red]Scope confirmation required[/bold red]")

        if not can(self.user, "confirm_scope"):
            self.console.print("[red]RBAC: only lead/admin may confirm scope.[/red]")
            self.audit.append(
                "scope_confirm_denied",
                self.user.username,
                {"role": self.user.role, "program_url": pol.program_url},
            )
            return

        table = Table(title="In-scope candidates (first 20)")
        table.add_column("Type")
        table.add_column("Value", overflow="fold")
        for st in pol.in_scope[:20]:
            table.add_row(st.type, st.value)
        self.console.print(table)

        ok = Confirm.ask(
            "Confirm scope is correct enough to proceed with passive actions?", default=False
        )
        if not ok:
            self.console.print(
                "[yellow]Scope NOT confirmed. Passive actions remain blocked.[/yellow]"
            )
            return

        ticket = Prompt.ask("Enter ticket / justification (e.g., SEC-2411)", default="N/A").strip()

        pol.requires_human_scope_confirmation = False
        pol.human_notes.append(
            f"Scope confirmed by {self.user.username} (role {self.user.role}) ticket={ticket}"
        )

        self.audit.append(
            "scope_confirmed",
            self.user.username,
            {
                "role": self.user.role,
                "program_url": pol.program_url,
                "justification": ticket,
                "in_scope_count": len(pol.in_scope),
                "out_of_scope_count": len(pol.out_of_scope),
            },
        )

        receipt_path = sign_scope_receipt(
            receipts_dir=Path(self.ctx.cache_dir) / "receipts",
            key_dir=Path(self.ctx.cache_dir) / "keys",
            program_url=pol.program_url,
            actor=self.user.username,
            role=self.user.role,
            justification=ticket,
            policy_fingerprint=pol.raw_text_fingerprint,
            in_scope_count=len(pol.in_scope),
            out_of_scope_count=len(pol.out_of_scope),
        )
        self.console.print(f"[green]Wrote scope receipt:[/green] {receipt_path.as_posix()}")
        self.audit.append(
            "scope_receipt_signed",
            self.user.username,
            {"role": self.user.role, "path": receipt_path.as_posix()},
        )

    def _execute_plan(self, guard: SafetyGuard) -> None:
        self.console.print("\n[bold]Executing plan (guarded)[/bold]\n")
        for idx, action in enumerate(self.ctx.plan, start=1):
            decision = guard.check_action(action)
            if not decision.allowed:
                self.console.print(f"[red]{idx}. BLOCKED[/red] {action.name} — {decision.reason}")
                continue

            if action.requires_approval and action.category == "passive_intel":
                if self.cfg.dry_run:
                    self.console.print(
                        f"[yellow]{idx}. DRY-RUN[/yellow] {action.name} ({action.target})"
                    )
                    continue
                if not self.cfg.auto_approve:
                    ok = Confirm.ask(
                        f"{idx}. Approve {action.name} on {action.target}?", default=False
                    )
                    if not ok:
                        self.audit.append(
                            "passive_action_denied",
                            self.user.username,
                            {
                                "role": self.user.role,
                                "action": action.name,
                                "target": action.target,
                            },
                        )
                        continue
                self.audit.append(
                    "passive_action_approved",
                    self.user.username,
                    {
                        "role": self.user.role,
                        "action": action.name,
                        "target": action.target,
                        "tool": action.metadata.get("tool"),
                    },
                )

            self._run_action(action)

    def _run_action(self, action: Action) -> None:
        if action.category != "passive_intel":
            return
        tool = action.metadata.get("tool")
        if tool == "resolve_a_records":
            self.ctx.passive_results[f"DNS_{action.target}"] = resolve_a_records(action.target)
        elif tool == "whois":
            self.ctx.passive_results[f"WHOIS_{action.target}"] = whois(action.target)

    def _write_reports(self) -> None:
        self.cfg.out_dir.mkdir(parents=True, exist_ok=True)
        key = self._safe_key()
        md_path = self.cfg.out_dir / f"report_{key}.md"
        js_path = self.cfg.out_dir / f"report_{key}.json"
        md_path.write_text(render_report_md(self.ctx), encoding="utf-8")
        js_path.write_text(render_report_json(self.ctx), encoding="utf-8")
        self.console.print(f"[green]Wrote:[/green] {md_path}")
        self.console.print(f"[green]Wrote:[/green] {js_path}")

    def _write_evidence_index(self) -> None:
        idx = write_evidence_index(Path.cwd(), self.ctx)
        self.console.print(f"[green]Wrote:[/green] {idx}")
        self.audit.append(
            "evidence_index_written",
            self.user.username,
            {"role": self.user.role, "path": idx.as_posix()},
        )

    def _display_policy_summary(self) -> None:
        pol = self.ctx.policy
        if not pol:
            return
        t = Table(title="Normalized Policy Summary")
        t.add_column("Field")
        t.add_column("Value", overflow="fold")
        t.add_row("Platform", pol.platform_hint)
        t.add_row("Title", pol.program_title)
        t.add_row("Scope confirmation required", str(pol.requires_human_scope_confirmation))
        t.add_row("In-scope count", str(len(pol.in_scope)))
        self.console.print(t)

    def _make_llm_suggestions(self) -> None:
        pol = self.ctx.policy
        if not pol:
            return
        llm = LLMClient.from_env()
        system = (
            "You are a compliance-first bug bounty assistant. "
            "ONLY produce scope questions, checklists, or ambiguity warnings. "
            "NO scanning or exploitation."
        )
        user = f"Program URL: {pol.program_url}\nTitle: {pol.program_title}\n\n{pol.rules_excerpt[:2500]}"
        msg = llm.suggest(system, user)
        dec = SafetyGuard(pol).check_text(msg)
        if dec.allowed:
            self.ctx.llm_suggestions.append(msg)
            self.audit.append("llm_suggestions_added", self.user.username, {"role": self.user.role})
        else:
            self.ctx.llm_suggestions.append(f"BLOCKED: {dec.reason}")
            self.audit.append(
                "llm_suggestions_blocked",
                self.user.username,
                {"role": self.user.role, "reason": dec.reason},
            )

    def _safe_key(self) -> str:
        from .cache import PolicyCache

        return PolicyCache.url_key(self.ctx.program_url)


from .findings import Finding
from .passive_tools import scan_python_repo


def scan_repo(path: Path) -> list[Finding]:
    findings = scan_python_repo(path)

    # Write scan reports (distinct from policy reports)
    write_scan_reports(findings, out_dir=Path("reports"))

    return findings


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen = {}
    for f in findings:
        key = (f.tool, f.rule_id, f.file_path, f.line)
        if key not in seen:
            seen[key] = f
    return list(seen.values())
