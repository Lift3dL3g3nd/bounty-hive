from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

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
        self.scope_confirmed = False
        self._build()

    def _build_log_tab(self) -> None:
        self.log_out = tk.Text(self.tab_log, wrap="word")
        self.log_out.pack(fill="both", expand=True, padx=10, pady=10)

    # ----------------------------
    # Core UI + Logging
    # ----------------------------

    def _build(self) -> None:
        self.root.title("Bounty-Hive")
        self.root.geometry("1100x700")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True)

        self.tab_scan = ttk.Frame(self.nb)
        self.tab_scope = ttk.Frame(self.nb)
        self.tab_log = ttk.Frame(self.nb)

        self.nb.add(self.tab_scan, text="Scan")
        self.nb.add(self.tab_scope, text="Scope")
        self.nb.add(self.tab_log, text="Log")

        self._build_scan_tab()
        self._build_scope_tab()
        self._build_log_tab()

    def log(self, msg: str) -> None:
        ts = datetime.utcnow().isoformat(timespec="seconds")
        line = f"[{ts}] {msg}\n"

        def _append() -> None:
            self.log_out.insert("end", line)
            self.log_out.see("end")

        # safe even if called from callbacks later
        self.root.after(0, _append)

    # ----------------------------
    # Scan tab (minimal, non-blocking stub)
    # ----------------------------

    def _build_scan_tab(self) -> None:
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

        self.scan_btn = ttk.Button(
            self.tab_scan_overview,
            text="Run Full Scan",
            command=self.on_run_scan,
        )
        self.scan_btn.pack(anchor="w", padx=10, pady=10)
        self.scan_btn.state(["disabled"])

        self.findings_out = tk.Text(self.tab_scan_findings, wrap="word")
        self.findings_out.pack(fill="both", expand=True, padx=10, pady=10)

    # ----------------------------
    # Scope tab (URL entry + in/out panes)
    # ----------------------------
    # NOTE: This method MUST exist exactly once.
    # Duplicate definitions will silently override earlier ones.

    def _build_scope_tab(self) -> None:
        # ensure the tab is clean (prevents stale widgets when reloading)
        for w in self.tab_scope.winfo_children():
            w.destroy()

        container = ttk.Frame(self.tab_scope)
        container.pack(fill="both", expand=True)

        # Top row: URL entry + button
        top = ttk.Frame(container)
        top.pack(fill="x", padx=12, pady=12)

        ttk.Label(
            top,
            text="Program URL / Scope Source:",
            font=("TkDefaultFont", 10, "bold"),
        ).pack(side="left")

        self.scope_entry = ttk.Entry(top)
        self.scope_entry.pack(side="left", fill="x", expand=True, padx=10)

        ttk.Button(
            top,
            text="Load Scope",
            command=self.on_load_scope,
        ).pack(side="left")

        # Middle: in/out panes
        body = ttk.Frame(container)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        left = ttk.Frame(body)
        right = ttk.Frame(body)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))

        ttk.Label(left, text="In Scope").pack(anchor="w")
        self.in_scope_txt = tk.Text(left, wrap="word", height=12)
        self.in_scope_txt.pack(fill="both", expand=True)

        ttk.Label(right, text="Out of Scope").pack(anchor="w")
        self.out_scope_txt = tk.Text(right, wrap="word", height=12)
        self.out_scope_txt.pack(fill="both", expand=True)

        # Bottom: confirm
        bottom = ttk.Frame(container)
        bottom.pack(fill="x", padx=12, pady=(0, 12))

        ttk.Button(
            bottom,
            text="Confirm Scope",
            command=self.on_confirm_scope,
        ).pack(side="right")

    def on_load_scope(self) -> None:
        source = self.scope_entry.get().strip()
        if not source:
            messagebox.showerror("Scope", "Please enter a scope URL or source.")
            return

        # Clear old data
        self.in_scope_txt.delete("1.0", "end")
        self.out_scope_txt.delete("1.0", "end")

        # Placeholder logic (safe/no fetching). You can wire real parsing later.
        clean = source.replace("https://", "").replace("http://", "").strip().strip("/")

        in_scope = [source, f"api.{clean}"]
        out_scope = [f"admin.{clean}", "*.internal"]

        self.in_scope_txt.insert("end", "\n".join(in_scope))
        self.out_scope_txt.insert("end", "\n".join(out_scope))

        self.log(f"Loaded scope source: {source}")

    def on_confirm_scope(self) -> None:
        try:
            policy = {
                "in_scope": [
                    ln for ln in self.in_scope_txt.get("1.0", "end").splitlines() if ln.strip()
                ],
                "out_of_scope": [
                    ln for ln in self.out_scope_txt.get("1.0", "end").splitlines() if ln.strip()
                ],
            }

            receipt = sign_scope_receipt(
                program_url=self.scope_entry.get().strip() or "local",
                normalized_policy=policy,
                actor=self.state.user,
            )

            self.audit.append(
                "scope_confirmed",
                self.state.user,
                {"receipt": receipt.get("receipt_id")},
            )

            self.log("Scope confirmed")
            messagebox.showinfo("Scope", "Scope confirmed.")
        except Exception as exc:
            self.log(f"Scope error: {exc}")
            messagebox.showerror("Scope error", str(exc))

    # ----------------------------
    # Log tab
    # ----------------------------

    def on_run_scan(self) -> None:
        if not self.scope_confirmed:
            messagebox.showwarning(
                "Scope not confirmed",
                "You must confirm scope before running a scan.",
            )
        self.log("Scan blocked: scope not confirmed")
        return

    # ----------------------------
    # Actions
    # ----------------------------

    def on_run_scan(self) -> None:
        self.findings_out.insert("end", "Scan executed (stub)\n")
        self.findings_out.see("end")
        self.log("Run Scan clicked (stub)")

    def main(
        *, user: str = "local", role: str = "viewer", cache_dir: str = ".bounty_hive_cache"
    ) -> int:
        root = tk.Tk()
        state = State(user=user, role=role, cache_dir=cache_dir)
        GUIApp(root, state)
        root.mainloop()
        return 0


def main(
    *, user: str = "local", role: str = "viewer", cache_dir: str = ".bounty_hive_cache"
) -> int:
    root = tk.Tk()
    state = State(user=user, role=role, cache_dir=cache_dir)
    GUIApp(root, state)
    root.mainloop()
    return 0
