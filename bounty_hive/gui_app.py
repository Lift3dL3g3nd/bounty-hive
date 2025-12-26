from __future__ import annotations

import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from .audit_bundle import make_audit_bundle
from .audit_log import AuditLog
from .auth import User, can
from .cache import PolicyCache
from .diffing import diff_policies
from .exports import export_policy_artifact
from .llm import LLMClient
from .models import Context
from .normalize import normalize_policy
from .orchestrator import Orchestrator, OrchestratorConfig
from .safety import SafetyGuard


class BountyHiveGUI(tk.Tk):
    def __init__(self, user: User, cache_dir: Path):
        super().__init__()
        self.title("Bounty Hive Enterprise (Kali-safe, passive-only)")
        self.geometry("1100x760")

        self.user = user
        self.cache_dir = cache_dir
        self.cache = PolicyCache(cache_dir)
        self.audit = AuditLog(cache_dir / "audit.log.jsonl")

        self.policy_by_url = {}
        self.scope_unlocked = tk.BooleanVar(value=False)

        self._build()

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Program URL").grid(row=0, column=0, sticky="w")
        self.url = ttk.Entry(top, width=90)
        self.url.grid(row=0, column=1, sticky="we", padx=8)

        btns = ttk.Frame(top)
        btns.grid(row=0, column=2, sticky="e")

        ttk.Button(btns, text="Normalize", command=self.on_normalize).pack(side="left", padx=4)
        ttk.Button(btns, text="Show Scope", command=self.on_show_scope).pack(side="left", padx=4)
        ttk.Button(btns, text="Run Orchestrator (dry-run)", command=self.on_run_orchestrator).pack(
            side="left", padx=4
        )

        self.btn_export = ttk.Button(btns, text="Export PDF", command=self.on_export_pdf)
        self.btn_export.pack(side="left", padx=4)

        top.columnconfigure(1, weight=1)

        lock = ttk.Frame(self, padding=(10, 0))
        lock.pack(fill="x")
        ttk.Label(
            lock,
            text="PASSIVE-ONLY MODE • RBAC ENFORCED • ALL ACTIONS AUDITED",
            foreground="darkred",
        ).pack(anchor="w")

        self.scope_cb = ttk.Checkbutton(
            lock,
            text="I CONFIRM scope is correct (unlock passive execution paths)",
            variable=self.scope_unlocked,
            command=self.on_scope_toggle,
        )
        self.scope_cb.pack(anchor="w")

        ttk.Label(
            lock,
            text=f"Logged in as {self.user.username} (role {self.user.role}).",
            foreground="#666",
        ).pack(anchor="w", pady=(0, 6))

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_scope = ttk.Frame(nb)
        self.tab_diff = ttk.Frame(nb)
        self.tab_llm = ttk.Frame(nb)
        self.tab_audit = ttk.Frame(nb)
        self.tab_log = ttk.Frame(nb)

        nb.add(self.tab_scope, text="Scope Viewer")
        nb.add(self.tab_diff, text="Policy Diff")
        nb.add(self.tab_llm, text="LLM (Read-only)")
        nb.add(self.tab_audit, text="Audit Bundle")
        nb.add(self.tab_log, text="Log")

        self._build_scope_tab()
        self._build_diff_tab()
        self._build_llm_tab()
        self._build_audit_tab()
        self._build_log_tab()

        self._apply_rbac_ui()

    def _apply_rbac_ui(self):
        can_export = can(self.user, "export") or self.user.role == "admin"
        self.btn_export.configure(state=("normal" if can_export else "disabled"))

        can_confirm = can(self.user, "confirm_scope") or self.user.role == "admin"
        self.scope_cb.configure(state=("normal" if can_confirm else "disabled"))

    def _build_scope_tab(self):
        cols = ("type", "value", "source", "notes")
        self.scope_tree = ttk.Treeview(self.tab_scope, columns=cols, show="headings", height=22)
        for c in cols:
            self.scope_tree.heading(c, text=c)
            self.scope_tree.column(c, width=240 if c == "value" else 120, anchor="w")
        self.scope_tree.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_diff_tab(self):
        frm = self.tab_diff
        top = ttk.Frame(frm, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="URLs to diff (2+), one per line:").grid(row=0, column=0, sticky="w")
        self.diff_urls = tk.Text(top, height=4, width=100)
        self.diff_urls.grid(row=1, column=0, sticky="we", pady=4)
        ttk.Button(top, text="Run Diff", command=self.on_run_diff).grid(row=1, column=1, padx=6)
        top.columnconfigure(0, weight=1)

        self.diff_out = tk.Text(frm, height=24)
        self.diff_out.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_llm_tab(self):
        frm = self.tab_llm
        ttk.Label(
            frm,
            text=(
                "Read-only LLM suggestions. Default backend MOCK (offline). "
                "To use local Ollama: set BOUNTY_HIVE_LLM_BACKEND=ollama."
            ),
            wraplength=1000,
        ).pack(anchor="w", padx=8, pady=8)
        ttk.Button(frm, text="Generate suggestions", command=self.on_llm_suggest).pack(
            anchor="w", padx=8
        )
        self.llm_out = tk.Text(frm, height=26)
        self.llm_out.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_audit_tab(self):
        frm = self.tab_audit
        self.include_cache = tk.BooleanVar(value=True)
        self.include_reports = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="Include .bounty_hive_cache", variable=self.include_cache).pack(
            anchor="w", padx=8, pady=(8, 0)
        )
        ttk.Checkbutton(frm, text="Include reports/", variable=self.include_reports).pack(
            anchor="w", padx=8
        )
        ttk.Button(frm, text="Create Audit Bundle…", command=self.on_audit_bundle).pack(
            anchor="w", padx=8, pady=8
        )
        self.audit_out = tk.Text(frm, height=18)
        self.audit_out.pack(fill="both", expand=True, padx=8, pady=8)

    def _build_log_tab(self):
        self.log = tk.Text(self.tab_log, height=32)
        self.log.pack(fill="both", expand=True, padx=8, pady=8)

    def _log(self, msg: str):
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def _get_url(self) -> str:
        u = self.url.get().strip()
        if not u:
            raise ValueError("Program URL is required.")
        return u

    def _ensure_policy(self, url: str):
        if url in self.policy_by_url:
            return self.policy_by_url[url]
        pol, src = normalize_policy(
            cache=self.cache,
            url=url,
            max_scope_items=200,
            overrides_path=Path("policy_overrides.json"),
            refresh=False,
        )
        self.policy_by_url[url] = pol
        self.audit.append(
            "policy_normalized",
            self.user.username,
            {"role": self.user.role, "program_url": url, "source": src},
        )
        self._log(f"Normalized {url} ({src})")
        return pol

    def on_scope_toggle(self):
        if self.scope_unlocked.get():
            if not can(self.user, "confirm_scope") and self.user.role != "admin":
                self.scope_unlocked.set(False)
                messagebox.showerror("RBAC", "Only lead/admin can confirm scope.")
                self.audit.append(
                    "gui_scope_unlock_denied", self.user.username, {"role": self.user.role}
                )
                return
            s = simpledialog.askstring(
                "Scope Confirmation",
                "Type CONFIRM to unlock passive execution:",
                initialvalue="CONFIRM",
            )
            if (s or "").strip().upper() != "CONFIRM":
                self.scope_unlocked.set(False)
                messagebox.showwarning("Not unlocked", "Scope remains locked.")
                return
            ticket = (
                simpledialog.askstring(
                    "Justification", "Enter ticket/justification (e.g., SEC-2411):"
                )
                or "N/A"
            )
            self.audit.append(
                "scope_unlock_gui",
                self.user.username,
                {"role": self.user.role, "justification": ticket},
            )
            self._log("Scope unlocked by user confirmation.")
        else:
            self._log("Scope lock enabled.")

    def on_normalize(self):
        try:
            if not can(self.user, "normalize") and self.user.role != "admin":
                raise PermissionError("RBAC: normalize requires analyst/lead/admin.")
            url = self._get_url()
            pol = self._ensure_policy(url)
            self._log(f"Title: {pol.program_title}")
            self._log(f"In-scope: {len(pol.in_scope)} | Out-of-scope: {len(pol.out_of_scope)}")
            messagebox.showinfo("OK", f"Normalized policy for:\n{url}")
        except Exception as e:
            messagebox.showerror("Normalize failed", str(e))

    def on_show_scope(self):
        try:
            url = self._get_url()
            pol = self._ensure_policy(url)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        for item in self.scope_tree.get_children():
            self.scope_tree.delete(item)

        for t in pol.in_scope:
            self.scope_tree.insert(
                "", "end", values=(t.type, t.value, t.source, getattr(t, "notes", ""))
            )
        for t in pol.out_of_scope:
            self.scope_tree.insert(
                "", "end", values=(t.type, t.value, t.source, getattr(t, "notes", ""))
            )

        self._log("Scope table updated.")

    def on_export_pdf(self):
        try:
            if not can(self.user, "export") and self.user.role != "admin":
                raise PermissionError("RBAC: export requires compliance/admin.")
            url = self._get_url()
            out = filedialog.asksaveasfilename(
                defaultextension=".pdf", filetypes=[("PDF", "*.pdf")]
            )
            if not out:
                return
            ok = export_policy_artifact(
                cache=self.cache,
                program_url=url,
                out_path=Path(out),
                fmt="pdf",
                overrides_path=Path("policy_overrides.json"),
                actor=self.user.username,
                role=self.user.role,
            )
            if ok:
                self.audit.append(
                    "export_pdf",
                    self.user.username,
                    {"role": self.user.role, "program_url": url, "out": out},
                )
                self._log(f"Exported PDF: {out}")
                messagebox.showinfo("Exported", out)
            else:
                raise RuntimeError("PDF export failed.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def on_run_diff(self):
        raw = self.diff_urls.get("1.0", "end").strip()
        urls = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if len(urls) < 2:
            messagebox.showerror("Need 2+", "Enter at least 2 URLs (one per line).")
            return
        try:
            report = diff_policies(
                self.cache, urls, refresh=False, overrides_path=Path("policy_overrides.json")
            )
            self.diff_out.delete("1.0", "end")
            self.diff_out.insert("end", report)
            self.audit.append(
                "diff_ran", self.user.username, {"role": self.user.role, "count": len(urls)}
            )
            self._log(f"Diff completed for {len(urls)} policies.")
        except Exception as e:
            messagebox.showerror("Diff failed", str(e))

    def on_llm_suggest(self):
        try:
            url = self._get_url()
            pol = self._ensure_policy(url)
            llm = LLMClient.from_env()
            system = (
                "You are a compliance-first bug bounty assistant. "
                "ONLY produce scope questions, checklists, or ambiguity warnings. "
                "NO scanning or exploitation."
            )
            user = (
                f"Program URL: {pol.program_url}\n"
                f"Title: {pol.program_title}\n\n"
                "Rules excerpt:\n"
                f"{(pol.rules_excerpt or '')[:2500]}\n\n"
                "In-scope candidates (first 25):\n"
                + "\n".join(f"- {t.type}: {t.value}" for t in pol.in_scope[:25])
            )
            msg = llm.suggest(system, user)
            dec = SafetyGuard(pol).check_text(msg)
            self.llm_out.delete("1.0", "end")
            if dec.allowed:
                self.llm_out.insert("end", msg.strip())
                self.audit.append(
                    "llm_suggestions_added_gui", self.user.username, {"role": self.user.role}
                )
                self._log("LLM suggestions generated.")
            else:
                self.llm_out.insert("end", f"LLM output blocked: {dec.reason}")
                self.audit.append(
                    "llm_suggestions_blocked_gui",
                    self.user.username,
                    {"role": self.user.role, "reason": dec.reason},
                )
                self._log("LLM suggestions blocked by guard.")
        except Exception as e:
            messagebox.showerror("LLM failed", str(e))

    def on_run_orchestrator(self):
        try:
            if not can(self.user, "normalize") and self.user.role != "admin":
                raise PermissionError("RBAC: normalize required.")
            if not self.scope_unlocked.get():
                raise PermissionError("Scope is locked. Confirm scope (toggle) before running.")
            url = self._get_url()
            pol = self._ensure_policy(url)

            mode = simpledialog.askstring(
                "Run Mode",
                "Type DRY for dry-run or LIVE for live passive actions:",
                initialvalue="DRY",
            )
            mode = (mode or "DRY").strip().upper()
            dry_run = True if mode != "LIVE" else False

            ctx = Context(
                program_url=url,
                cache_dir=str(self.cache_dir),
                dry_run=dry_run,
                auto_approve=False,
                llm_suggest=True,
                now_utc=datetime.utcnow().isoformat(timespec="seconds") + "Z",
                actor=self.user.username,
                role=self.user.role,
                policy=pol,
            )

            out_dir = Path.cwd() / "reports"
            orch = Orchestrator(
                OrchestratorConfig(out_dir=out_dir, dry_run=dry_run, auto_approve=False), ctx
            )
            self.audit.append(
                "gui_orchestrator_run",
                self.user.username,
                {"role": self.user.role, "program_url": url, "dry_run": dry_run},
            )
            orch.run()

            self._log(f"Orchestrator finished (dry_run={dry_run}). Reports in {out_dir.as_posix()}")
            messagebox.showinfo("Done", f"Orchestrator finished (dry_run={dry_run}).")
        except Exception as e:
            messagebox.showerror("Run failed", str(e))

    def on_audit_bundle(self):
        if not can(self.user, "audit") and self.user.role != "admin":
            messagebox.showerror("RBAC", "Audit bundle requires compliance/admin.")
            return
        project_root = Path.cwd()
        if not (project_root / "bounty_hive").exists():
            messagebox.showerror("Error", "Run GUI from bounty-hive directory.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP", "*.zip")])
        if not out:
            return
        try:
            z = make_audit_bundle(
                project_root=project_root,
                out_zip=Path(out),
                include_cache=bool(self.include_cache.get()),
                include_reports=bool(self.include_reports.get()),
            )
            self.audit_out.delete("1.0", "end")
            self.audit_out.insert(
                "end", f"Created:\n{z}\n\nAlso wrote MANIFEST.sha256 in project root.\n"
            )
            self.audit.append(
                "audit_bundle_created", self.user.username, {"role": self.user.role, "out": str(z)}
            )
            self._log(f"Audit bundle created: {z}")
            messagebox.showinfo("Audit bundle created", str(z))
        except Exception as e:
            messagebox.showerror("Audit bundle failed", str(e))


def main(user: str = "local", role: str = "analyst", cache_dir: str = ".bounty_hive_cache") -> None:
    u = User(username=user, role=role)
    app = BountyHiveGUI(u, Path(cache_dir))
    app.mainloop()
