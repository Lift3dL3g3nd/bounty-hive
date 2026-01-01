from __future__ import annotations

import tkinter as tk

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

from .audit_log import AuditLog
from .receipts import sign_scope_receipt

import hashlib
import json


def fingerprint_policy(policy: dict) -> str:
    """
    Create a stable fingerprint of the scope policy.
    """
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_scope_source(source: str) -> tuple[list[str], list[str]]:
    """
    Load scope from:
    - directory containing allowlist.txt / blocklist.txt
    - single file (treated as allowlist)
    - raw pasted text (one entry per line)
    """
    p = Path(source).expanduser()

    allow: list[str] = []
    deny: list[str] = []

    if p.exists() and p.is_dir():
        allow_path = p / "allowlist.txt"
        deny_path = p / "blocklist.txt"

        if allow_path.exists():
            allow = [
                ln.strip()
                for ln in allow_path.read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]

        if deny_path.exists():
            deny = [
                ln.strip()
                for ln in deny_path.read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]

    elif p.exists() and p.is_file():
        allow = [
            ln.strip()
            for ln in p.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]

    else:
        # raw pasted scope
        allow = [
            ln.strip()
            for ln in source.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]

    return allow, deny


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
            messagebox.showerror("Scope", "Please enter a scope source.")
            return

        try:
            allow, deny = parse_scope_source(source)

            if not allow:
                raise ValueError("No in-scope entries found.")

            self.in_scope_txt.delete("1.0", "end")
            self.out_scope_txt.delete("1.0", "end")

            self.in_scope_txt.insert("end", "\n".join(allow))
            if deny:
                self.out_scope_txt.insert("end", "\n".join(deny))

            self.loaded_scope = {
                "source": source,
                "in_scope": allow,
                "out_of_scope": deny,
            }

            self.log(f"Loaded scope from: {source}")

        except Exception as exc:
            messagebox.showerror("Scope error", str(exc))
            self.log(f"Scope load failed: {exc}")

    def on_confirm_scope(self) -> None:
        if not hasattr(self, "loaded_scope"):
            messagebox.showwarning("Scope", "Load scope before confirming.")
            return

        policy = {
            "in_scope": [
                ln for ln in self.in_scope_txt.get("1.0", "end").splitlines() if ln.strip()
            ],
            "out_of_scope": [
                ln for ln in self.out_scope_txt.get("1.0", "end").splitlines() if ln.strip()
            ],
        }

        try:
            policy_fp = fingerprint_policy(policy)

            receipt = sign_scope_receipt(
                Path(self.state.cache_dir) / "receipts",
                Path(self.state.cache_dir) / "keys",
                program_url=self.loaded_scope["source"],
                actor=self.state.user,
                role=self.state.role,
                justification="Scope confirmed via GUI",
                policy_fingerprint=policy_fp,
                in_scope_count=len(policy["in_scope"]),
                out_of_scope_count=len(policy["out_of_scope"]),
            )

            self.audit.append(
                "scope_confirmed",
                self.state.user,
                {"receipt_path": str(receipt)},
            )
            assert isinstance(receipt, Path)

            self.scope_confirmed = True
            self.scan_btn.state(["!disabled"])

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
            return

        # Disable button to prevent double-clicks
        self.scan_btn.state(["disabled"])

        self.log("Scan started")
        self.findings_out.insert("end", "Starting scan...\n")
        self.findings_out.see("end")

        # Run scan asynchronously so GUI doesn't freeze
        self.root.after(100, self._run_scan_job)

    def _run_scan_job(self) -> None:
        try:
            in_scope = self.in_scope_txt.get("1.0", "end").splitlines()
            in_scope = [x.strip() for x in in_scope if x.strip()]

            for target in in_scope:
                # SAFE placeholder scan logic
                self.findings_out.insert(
                    "end",
                    f"[OK] Enumerated target: {target}\n",
                )
                self.log(f"Scanned target: {target}")

            self.findings_out.insert("end", "Scan complete.\n")
            self.findings_out.see("end")
            self.log("Scan completed successfully")

        except Exception as exc:
            self.log(f"Scan error: {exc}")
            messagebox.showerror("Scan error", str(exc))

        finally:
            # ALWAYS re-enable scan button
            self.scan_btn.state(["!disabled"])

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
