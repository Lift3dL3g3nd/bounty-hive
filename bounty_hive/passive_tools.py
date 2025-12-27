from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .findings import Finding


# -----------------------------
# Network helpers
# -----------------------------


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
        p = subprocess.run(
            ["whois", domain_or_ip],
            capture_output=True,
            text=True,
            timeout=25,
        )
        results["output"] = (p.stdout or "")[:20000]
        if p.returncode != 0:
            results["error"] = (p.stderr or "")[:2000].strip()
    except Exception as e:
        results["error"] = str(e)

    return results


# -----------------------------
# Subprocess helper
# -----------------------------


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


# -----------------------------
# Bandit (repo scan)
# -----------------------------
def run_bandit(repo_path: Path, output_dir: Path) -> Path:
    """
    Run Bandit in JSON mode against a repository and write results to disk.
    Read-only, non-executing.
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


def normalize_bandit_findings(data: dict[str, Any]) -> list[Finding]:
    """
    Normalize raw Bandit JSON into Finding objects.
    """
    findings: list[Finding] = []

    for item in data.get("results", []):
        findings.append(
            Finding(
                tool="bandit",
                rule_id=item.get("test_id", ""),
                severity=item.get("issue_severity", "UNKNOWN"),
                title=item.get("issue_text", ""),
                description=item.get("issue_text", ""),
                file_path=item.get("filename"),
                line=item.get("line_number"),
                evidence=item,
            )
        )

    return findings


def scan_bandit(repo: Path) -> list[Finding]:
    proc = _run(
        ["bandit", "-r", ".", "-f", "json"],
        cwd=repo,
    )

    if not proc.stdout or not proc.stdout.strip():
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError("Bandit returned invalid JSON.\nSTDERR:\n" + (proc.stderr or "")) from e

    findings: list[Finding] = []

    for item in data.get("results", []):
        findings.append(
            Finding(
                tool="bandit",
                rule_id=item.get("test_id", ""),
                severity=item.get("issue_severity", "UNKNOWN"),
                title=item.get("issue_text", ""),
                description=item.get("issue_text", ""),
                file_path=item.get("filename"),
                line=item.get("line_number"),
                evidence=item,
            )
        )

    return findings


# -----------------------------
# pip-audit
# -----------------------------


def scan_pip_audit(repo: Path) -> list[Finding]:
    proc = _run(
        ["pip-audit", "-f", "json"],
        cwd=repo,
    )

    if not proc.stdout or not proc.stdout.strip():
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            "pip-audit returned invalid JSON.\nSTDERR:\n" + (proc.stderr or "")
        ) from e

    findings: list[Finding] = []

    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append(
                Finding(
                    tool="pip-audit",
                    rule_id=vuln.get("id", ""),
                    severity=vuln.get("severity", "UNKNOWN"),
                    title=vuln.get("id", ""),
                    description=vuln.get("description", ""),
                    file_path=None,
                    line=None,
                    evidence=vuln,
                )
            )

    return findings


# -----------------------------
# Python repo scan (Bandit w/ excludes)
# -----------------------------

DEFAULT_EXCLUDES = [
    ".venv",
    ".git",
    "__pycache__",
    "tests",
    "node_modules",
    "dist",
    "build",
]


def scan_python_repo(path: Path) -> list[Finding]:
    path = path.resolve()
    exclude = ",".join(DEFAULT_EXCLUDES)

    cmd = [
        "bandit",
        "-r",
        str(path),
        "-f",
        "json",
        "--exclude",
        exclude,
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if proc.returncode not in (0, 1):
        raise RuntimeError(f"Bandit failed: {proc.stderr}")

    if not proc.stdout or not proc.stdout.strip():
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []

    for issue in data.get("results", []):
        findings.append(
            Finding(
                tool="bandit",
                rule_id=issue.get("test_id", "UNKNOWN"),
                severity=issue.get("issue_severity", "LOW"),
                title=issue.get("issue_text"),
                description=issue.get("issue_text"),
                file_path=issue.get("filename"),
                line=issue.get("line_number"),
                evidence=issue,
            )
        )

    return findings
