from __future__ import annotations

import shutil
import socket
import subprocess
from typing import Any
import json
import subprocess
from pathlib import Path
from typing import Any


def resolve_a_records(domain: str) -> dict[str, Any]:
    results = {"domain": domain, "addresses": [], "error": ""}
    try:
        infos = socket.getaddrinfo(domain, None)
        addrs = sorted({info[4][0] for info in infos if info and info[4]})
        results["addresses"] = addrs
    except Exception as e:
        results["error"] = str(e)
    return results


def whois(domain_or_ip: str) -> dict[str, Any]:
    results = {"query": domain_or_ip, "output": "", "error": ""}
    if not shutil.which("whois"):
        results["error"] = "whois binary not found."
        return results
    try:
        p = subprocess.run(["whois", domain_or_ip], capture_output=True, text=True, timeout=25)
        results["output"] = (p.stdout or "")[:20000]
        if p.returncode != 0:
            results["error"] = (p.stderr or "")[:2000].strip()
    except Exception as e:
        results["error"] = str(e)
    return results
def run_bandit(repo_path: Path, output_dir: Path) -> Path:
    """
    Run Bandit in JSON mode against a repository.
    Read-only, no execution.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "bandit_findings.json"

    cmd = [
        "bandit",
        "-r",
        str(repo_path),
        "-f",
        "json",
        "-o",
        str(out_file),
    ]

    subprocess.run(
        cmd,
        check=False,  # Bandit exits non-zero if it finds issues
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    return out_file
