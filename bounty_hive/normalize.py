from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .adapters.base import AdapterRegistry
from .adapters.generic import GenericAdapter
from .cache import PolicyCache
from .fetch import fetch_html
from .overrides import apply_overrides, load_overrides


def normalize_policy(
    cache: PolicyCache,
    url: str,
    max_scope_items: int,
    overrides_path: Path,
    refresh: bool = False,
):
    """
    Normalize a program policy into a deterministic, versioned structure.

    Side effects:
    - caches normalized policy
    - appends an immutable audit-chain record
    """

    # --- Load from cache if allowed ---
    if not refresh:
        existing = cache.load_by_url(url)
        if existing:
            ovs = load_overrides(overrides_path)
            existing = apply_overrides(existing, ovs) if ovs else existing
            return existing, "cache+overrides" if ovs else "cache"

    # --- Fetch or load HTML ---
    html_path = cache.html_path(url)
    if html_path.exists() and not refresh:
        html = html_path.read_text(encoding="utf-8")
    else:
        html = fetch_html(url, html_path)

    # --- FIXED: timezone-aware UTC (no deprecation warning) ---
    fetched_at_utc = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    # --- Adapter selection ---
    reg = AdapterRegistry()
    reg.register(GenericAdapter())
    adapter = reg.pick(url) or GenericAdapter()

    # --- Normalize policy ---
    pol = adapter.normalize(url, html, fetched_at_utc, html_path.as_posix())

    # --- Apply overrides (if any) ---
    ovs = load_overrides(overrides_path)
    if ovs:
        pol = apply_overrides(pol, ovs)

    # --- Persist normalized policy ---
    cache.save(pol, url)

    # --- Append audit-chain record (lazy imports to avoid circular deps) ---
    from . import audit_chain
    from .audit_store import AuditStore
    from .audit_utils import hash_policy

    audit_store = AuditStore(cache.cache_dir / "audit_chain.json")
    payload_hash = hash_policy(pol)

    record = audit_chain.AuditRecord.create(
        record_type="policy.normalized",
        subject_id=pol.program_url,
        schema_version=pol.schema_version,
        actor="system",
        payload_hash=payload_hash,
        previous_hash=audit_store.last_hash(),
    )

    audit_store.append(record)

    return pol, "fresh+overrides" if ovs else "fresh"
