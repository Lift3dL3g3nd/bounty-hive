from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console

from .cache import PolicyCache
from .models import Context
from .normalize import normalize_policy
from .orchestrator import Orchestrator, OrchestratorConfig


def run_many(
    program_urls: list[str],
    cache_dir: Path,
    out_dir: Path,
    dry_run: bool,
    auto_approve: bool,
    max_scope_items: int,
    overrides_path: Path,
    llm_suggest: bool,
    actor: str,
    role: str,
) -> None:
    console = Console()
    cache = PolicyCache(cache_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Bounty Hive Enterprise[/bold] — running {len(program_urls)} program(s)\n")

    for url in program_urls:
        pol, source = normalize_policy(
            cache,
            url,
            max_scope_items=max_scope_items,
            overrides_path=overrides_path,
            refresh=False,
        )
        console.print(f"[cyan]Normalized:[/cyan] {url} ({source})")

        ctx = Context(
            program_url=url,
            cache_dir=str(cache_dir),
            dry_run=dry_run,
            auto_approve=auto_approve,
            llm_suggest=llm_suggest,
            now_utc=datetime.utcnow().isoformat(timespec="seconds") + "Z",
            actor=actor,
            role=role,
            policy=pol,
        )

        orch = Orchestrator(
            OrchestratorConfig(out_dir=out_dir, dry_run=dry_run, auto_approve=auto_approve), ctx
        )
        orch.run()
