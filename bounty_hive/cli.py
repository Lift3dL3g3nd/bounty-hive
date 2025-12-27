from __future__ import annotations

import argparse
from pathlib import Path

from .orchestrator import scan_repo
from .runner import run_many
from .gui_app import main as gui_main


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
        for f in scan_repo(args.path):
            print(f"[{f.tool}] {f.severity} {f.rule_id}")
        return

    if args.cmd == "gui":
        gui_main(user="local", role="analyst", cache_dir=".bounty_hive_cache")
        return


if __name__ == "__main__":
    main()
