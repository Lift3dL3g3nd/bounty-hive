from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Iterable


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(
    root: Path, exclude_dirs: Iterable[str] = (".venv", "__pycache__", ".pytest_cache")
) -> list[Path]:
    root = root.resolve()
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = set(p.relative_to(root).parts)
        if any(x in parts for x in exclude_dirs):
            continue
        out.append(p)
    return sorted(out)


def write_manifest(root: Path, out_path: Path | None = None) -> Path:
    root = root.resolve()
    if out_path is None:
        out_path = root / "MANIFEST.sha256"
    entries = []
    for f in iter_files(root):
        rel = f.relative_to(root).as_posix()
        entries.append((rel, _sha256_file(f)))
    lines = [f"{sha}  {rel}" for rel, sha in entries]
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def make_audit_bundle(
    project_root: Path, out_zip: Path, include_cache: bool = True, include_reports: bool = True
) -> Path:
    project_root = project_root.resolve()
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    manifest_path = write_manifest(project_root)

    def allow(p: Path) -> bool:
        rel = p.relative_to(project_root).as_posix()
        if (
            rel.startswith(".venv/")
            or rel.startswith("__pycache__/")
            or rel.startswith(".pytest_cache/")
        ):
            return False
        if not include_cache and rel.startswith(".bounty_hive_cache/"):
            return False
        if not include_reports and rel.startswith("reports/"):
            return False
        return True

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(manifest_path, arcname=manifest_path.relative_to(project_root).as_posix())
        for p in project_root.rglob("*"):
            if not p.is_file():
                continue
            if not allow(p):
                continue
            arc = p.relative_to(project_root).as_posix()
            if arc == manifest_path.relative_to(project_root).as_posix():
                continue
            z.write(p, arcname=arc)

    return out_zip
