from __future__ import annotations

import argparse
from bounty_hive.reporting.sarif import findings_to_sarif
from bounty_hive.reporting.hash_utils import sha256_canonical

from datetime import datetime, timezone
from bounty_hive.models import Context
from pathlib import Path

from collections import defaultdict
import json

from .orchestrator import scan_repo
from .runner import run_many
from bounty_hive.reporting.sarif import findings_to_sarif
from bounty_hive.reporting.writer import write_report

from .gui_app import main as gui_main


def dedupe_findings(findings):
    seen = set()
    unique = []

    for f in findings:
        key = (f.tool, f.rule_id, f.file_path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def filter_by_severity(findings, minimum="LOW"):
    min_level = SEVERITY_ORDER.get(minimum.upper(), 1)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity.upper(), 0) >= min_level]


def group_by_rule(findings):
    grouped = defaultdict(list)
    for f in findings:
        grouped[f.rule_id].append(f)
    return grouped


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bounty-hive",
        description="Enterprise-grade, passive-only security analysis platform",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    # run
    run_cmd = sub.add_parser("run", help="Normalize program policies")
    run_cmd.add_argument("program_urls", nargs="+")
    run_cmd.add_argument("--cache-dir", default=".bounty_hive_cache")
    run_cmd.add_argument("--out-dir", default="reports")
    run_cmd.add_argument("--dry-run", action="store_true")

    # scan
    scan_cmd = sub.add_parser("scan", help="Passive security scanning")
    scan_cmd.add_argument("path", type=Path)

    scan_cmd.add_argument(
        "--min-severity",
        default="LOW",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity to report",
    )

    scan_cmd.add_argument(
        "--verbose",
        action="store_true",
        help="Show individual findings",
    )

    scan_cmd.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON",
    )

    scan_cmd.add_argument(
        "--sarif",
        action="store_true",
        help="Output findings in SARIF format",
    )

    # gui
    sub.add_parser("gui", help="Launch GUI")

    args = parser.parse_args()

    if args.cmd == "run":
        run_many(
            program_urls=args.program_urls,
            cache_dir=Path(args.cache_dir),
            out_dir=Path(args.out_dir),
            dry_run=args.dry_run,
            auto_approve=False,
            max_scope_items=120,
            overrides_path=Path("policy_overrides.json"),
            llm_suggest=False,
            actor="local",
            role="analyst",
        )
        return

    if args.cmd == "scan":
        print("Starting scan…")

        ctx = Context(
            actor="local",
            role="analyst",
            cache_dir=".bounty_hive_cache",
            policy=None,
            program_url=str(args.path),
            dry_run=True,
            auto_approve=False,
            llm_suggest=False,
            now_utc=datetime.now(timezone.utc),
        )

        findings, _, _ = scan_repo(args.path, ctx)
        findings = dedupe_findings(findings)
        findings = filter_by_severity(findings, args.min_severity)
        # ---- SARIF generation (deterministic, core-safe) ----
        sarif_doc = findings_to_sarif(findings)
        sarif_hash = sha256_canonical(sarif_doc)

        # Temporary visibility (safe: hash only)
        print(f"[audit] SARIF hash: {sarif_hash}")

        grouped = group_by_rule(findings)

        if args.json:
            output = {
                "total": len(findings),
                "by_rule": {rule: len(items) for rule, items in grouped.items()},
                "findings": [
                    {
                        "tool": f.tool,
                        "severity": f.severity,
                        "rule_id": f.rule_id,
                        "file": f.file_path,
                        "line": f.line,
                    }
                    for f in findings
                ],
            }
            print(json.dumps(output, indent=2))
            return
        if args.json:
            output = {...}
            print(json.dumps(output, indent=2))
            return

        # ✅ SARIF GOES HERE
        if args.sarif:
            sarif = findings_to_sarif(findings)
            print(json.dumps(sarif, indent=2))
            return

        if args.sarif:
            sarif = findings_to_sarif(findings)
            print(json.dumps(sarif, indent=2))
            return

        print("Scan complete.")
        print(f"Findings (severity ≥ {args.min_severity}): {len(findings)}\n")

        if findings:
            print("Rule Summary:")
            for rule, items in sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True):
                sev = items[0].severity
                print(f"- {rule} ({sev}): {len(items)}")

        if args.verbose:
            print("\nDetailed Findings:")
            for f in findings:
                loc = f"{f.file_path}:{f.line}" if f.file_path else "N/A"
                print(f"[{f.tool}] {f.severity} {f.rule_id} {loc}")

                return
