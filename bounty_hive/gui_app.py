from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass
from pathlib import Path

from .audit_log import AuditLog
from .receipts import sign_scope_receipt


@dataclass
class State:
    user: str
    role: str
    cache_dir: str


class GUIApp:
    def __init__(self, root: tk.Tk, state: State):
        self.root = root
        self.state = state
        self.audit = AuditLog(Path(state.cache_dir) / "audit.log.jsonl")
        self._build()

    # -------------------------------------------------
    # BUILD ROOT UI
    # -------------------------------------------------

    def _build(self):
        self.root.geometry("1000x650")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True)

        self.tab_scan = ttk.Frame(nb)
        self.tab_scope = ttk.Frame(nb)
        self.tab_diff = ttk.Frame(nb)
        self.tab_llm = ttk.Frame(nb)
        self.tab_audit = ttk.Frame(nb)
        self.tab_log = ttk.Frame(nb)

        nb.add(self.tab_scan, text="Scan")
        nb.add(self.tab_scope, text="Scope")
        nb.add(self.tab_diff, text="Policy Diff")
        nb.add(self.tab_llm, text="LLM (Read-only)")
        nb.add(self.tab_audit, text="Audit Bundle")
        nb.add(self.tab_log, text="Log")

        self._build_scan_tab()
        self._build_scope_tab()
        self._build_diff_tab()
        self._build_llm_tab()
        self._build_audit_tab()
        self._build_log_tab()

    # -------------------------------------------------
    # SCAN TAB
    # -------------------------------------------------

    def _build_scan_tab(self):
        frm = self.tab_scan

        ttk.Label(
            frm,
            text="Scanning & Analysis",
            font=("TkDefaultFont", 11, "bold"),
        ).pack(anchor="w", padx=10, pady=(10, 6))

        tools_nb = ttk.Notebook(frm)
        tools_nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_scan_overview = ttk.Frame(tools_nb)
        self.tab_scan_findings = ttk.Frame(tools_nb)

        tools_nb.add(self.tab_scan_overview, text="Overview")
        tools_nb.add(self.tab_scan_findings, text="Findings")

        self._build_scan_overview_tab()
        self._build_scan_findings_tab()

    def _build_scan_overview_tab(self):
        ttk.Button(
            self.tab_scan_overview,
            text="Run Full Scan",
            command=self.on_run_scan,
        ).pack(anchor="w", padx=10, pady=10)

    def _build_scan_findings_tab(self):
        self.findings_out = tk.Text(self.tab_scan_findings)
        self.findings_out.pack(fill="both", expand=True, padx=10, pady=10)

    # -------------------------------------------------
    # OTHER TABS
    # -------------------------------------------------

    def _build_scope_tab(self):
        ttk.Label(
            self.tab_scope,
            text="Scope confirmation",
        ).pack(anchor="w", padx=10, pady=10)

        ttk.Button(
            self.tab_scope,
            text="Confirm Scope",
            command=self.on_confirm_scope,
        ).pack(anchor="w", padx=10)

    def _build_diff_tab(self):
        ttk.Label(
            self.tab_diff,
            text="Policy diff (placeholder)",
        ).pack(padx=10, pady=10)

    def _build_llm_tab(self):
        ttk.Label(
            self.tab_llm,
            text="LLM output is analysis-only and non-exploitative.",
            foreground="darkred",
        ).pack(anchor="w", padx=10, pady=10)

        txt = tk.Text(self.tab_llm, height=20)
        txt.insert("end", "LLM explanations will appear here.")
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_audit_tab(self):
        ttk.Label(
            self.tab_audit,
            text="Audit bundle (placeholder)",
        ).pack(padx=10, pady=10)

    def _build_log_tab(self):
        self.log_out = tk.Text(self.tab_log)
        self.log_out.pack(fill="both", expand=True, padx=10, pady=10)

    # -------------------------------------------------
    # ACTIONS
    # -------------------------------------------------

    def on_confirm_scope(self):
        try:
            receipt = sign_scope_receipt(
                program_url="local",
                normalized_policy={},
                actor=self.state.user,
            )
            self.audit.append(
                "scope_confirmed",
                self.state.user,
                {"receipt": receipt.get("receipt_id")},
            )
            messagebox.showinfo("Scope", "Scope confirmed.")
        except Exception as exc:
            messagebox.showerror("Scope error", str(exc))

    def on_run_scan(self):
        self.findings_out.insert("end", "Scan executed (stub)\n")


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------


def main(*, user="local", role="viewer", cache_dir=".bounty_hive_cache") -> int:
    root = tk.Tk()
    root.title("Bounty-Hive")

    state = State(
        user=user,
        role=role,
        cache_dir=cache_dir,
    )

    GUIApp(root, state)
    root.mainloop()
    return 0
