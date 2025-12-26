from __future__ import annotations

import argparse
from pathlib import Path

from .audit_bundle import make_audit_bundle
from .audit_log import AuditLog
from .auth import User, can
from .cache import PolicyCache
from .diffing import diff_policies
from .exports import export_policy_artifact
from .receipts import verify_scope_receipt
from .runner import run_many


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bounty-hive",
        description="Enterprise-grade, passive-only policy normalizer + evidence tool.",
    )
    p.add_argument(
        "--user", default="local", help="Actor username for audit trail (e.g., alice@company)."
    )
    p.add_argument(
        "--role", default="analyst", choices=["viewer", "analyst", "lead", "compliance", "admin"]
    )
    p.add_argument(
        "--audit-log", default=".bounty_hive_cache/audit.log.jsonl", help="Audit log path (JSONL)."
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run planner for one or more program URLs.")
    run.add_argument("program_urls", nargs="+")
    run.add_argument("--cache-dir", default=".bounty_hive_cache")
    run.add_argument("--out-dir", default="reports")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--yes", action="store_true")
    run.add_argument("--max-scope-items", type=int, default=120)
    run.add_argument("--overrides", default="policy_overrides.json")
    run.add_argument("--llm-suggest", action="store_true")

    d = sub.add_parser("diff", help="Diff two or more program policies.")
    d.add_argument("program_urls", nargs="+")
    d.add_argument("--cache-dir", default=".bounty_hive_cache")
    d.add_argument("--refresh", action="store_true")
    d.add_argument("--overrides", default="policy_overrides.json")

    s = sub.add_parser("show", help="Show cached normalized policy JSON.")
    s.add_argument("program_url")
    s.add_argument("--cache-dir", default=".bounty_hive_cache")

    e = sub.add_parser("export", help="Export cached policy as JSON/PDF/MD.")
    e.add_argument("program_url")
    e.add_argument("--cache-dir", default=".bounty_hive_cache")
    e.add_argument("--format", choices=["json", "pdf", "md"], default="pdf")
    e.add_argument("--out", required=True)
    e.add_argument("--overrides", default="policy_overrides.json")

    g = sub.add_parser("gui", help="Launch GUI (Kali: install python3-tk).")
    g.add_argument("--cache-dir", default=".bounty_hive_cache")

    ab = sub.add_parser("audit-bundle", help="Create audit ZIP + MANIFEST.sha256.")
    ab.add_argument("--out", required=True)
    ab.add_argument("--include-cache", action="store_true", default=False)
    ab.add_argument("--include-reports", action="store_true", default=False)

    av = sub.add_parser("audit-verify", help="Verify tamper-evident audit log chain.")
    av.add_argument("--audit-log", default=".bounty_hive_cache/audit.log.jsonl")

    rv = sub.add_parser("receipt-verify", help="Verify a signed scope receipt.")
    rv.add_argument("--receipt", required=True)
    rv.add_argument("--pubkey", default=".bounty_hive_cache/receipts/scope_receipt_ed25519.pub")

    return p


def main() -> int:
    p = _build_parser()
    args = p.parse_args()

    user = User(username=str(args.user), role=str(args.role))
    alog = AuditLog(Path(getattr(args, "audit_log", ".bounty_hive_cache/audit.log.jsonl")))

    if args.cmd == "run":
        if not can(user, "normalize"):
            print("RBAC: permission denied (normalize).")
            return 10
        alog.append(
            "run_invoked",
            user.username,
            {"role": user.role, "program_urls": list(args.program_urls)},
        )
        run_many(
            program_urls=args.program_urls,
            cache_dir=Path(args.cache_dir),
            out_dir=Path(args.out_dir),
            dry_run=bool(args.dry_run),
            auto_approve=bool(args.yes),
            max_scope_items=int(args.max_scope_items),
            overrides_path=Path(args.overrides),
            llm_suggest=bool(args.llm_suggest),
            actor=user.username,
            role=user.role,
        )
        return 0

    if args.cmd == "diff":
        if not can(user, "read"):
            print("RBAC: permission denied (read).")
            return 10
        cache = PolicyCache(Path(args.cache_dir))
        alog.append(
            "diff_invoked", user.username, {"role": user.role, "count": len(args.program_urls)}
        )
        report = diff_policies(
            cache,
            args.program_urls,
            refresh=bool(args.refresh),
            overrides_path=Path(args.overrides),
        )
        print(report)
        return 0

    if args.cmd == "show":
        if not can(user, "read"):
            print("RBAC: permission denied (read).")
            return 10
        cache = PolicyCache(Path(args.cache_dir))
        pol = cache.load_by_url(args.program_url)
        if not pol:
            print("No cached policy found.")
            return 3
        import json

        print(json.dumps(pol.to_json(), indent=2, sort_keys=True))
        return 0

    if args.cmd == "export":
        if not can(user, "export") and user.role != "admin":
            print("RBAC: permission denied (export requires compliance/admin).")
            return 10
        cache = PolicyCache(Path(args.cache_dir))
        alog.append(
            "export_invoked",
            user.username,
            {
                "role": user.role,
                "program_url": args.program_url,
                "fmt": args.format,
                "out": args.out,
            },
        )
        ok = export_policy_artifact(
            cache=cache,
            program_url=args.program_url,
            out_path=Path(args.out),
            fmt=args.format,
            overrides_path=Path(args.overrides),
            actor=user.username,
            role=user.role,
        )
        return 0 if ok else 4

    if args.cmd == "gui":
        from .gui_app import main as gui_main

        if not can(user, "read"):
            print("RBAC: permission denied (read).")
            return 10
        alog.append("gui_launched", user.username, {"role": user.role})
        gui_main(user=user.username, role=user.role, cache_dir=str(args.cache_dir))
        return 0

    if args.cmd == "audit-bundle":
        if not can(user, "audit") and user.role != "admin":
            print("RBAC: permission denied (audit requires compliance/admin).")
            return 10
        alog.append("audit_bundle_invoked", user.username, {"role": user.role, "out": args.out})
        make_audit_bundle(
            Path.cwd(),
            Path(args.out),
            include_cache=bool(args.include_cache),
            include_reports=bool(args.include_reports),
        )
        print(args.out)
        return 0

    if args.cmd == "audit-verify":
        if not can(user, "audit") and user.role != "admin":
            print("RBAC: permission denied (audit).")
            return 10
        ok, msg = AuditLog(Path(args.audit_log)).verify()
        print(("OK" if ok else "FAIL") + " - " + msg)
        return 0 if ok else 11

    if args.cmd == "receipt-verify":
        if not can(user, "audit") and user.role != "admin":
            print("RBAC: permission denied (audit).")
            return 10
        ok, msg = verify_scope_receipt(Path(args.receipt), Path(args.pubkey))
        print(("OK" if ok else "FAIL") + " - " + msg)
        return 0 if ok else 11

    return 1
