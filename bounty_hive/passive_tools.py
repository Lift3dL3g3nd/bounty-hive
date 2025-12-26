from __future__ import annotations

import shutil
import socket
import subprocess
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
