from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .adapters.base import AdapterRegistry
from .adapters.generic import GenericAdapter
from .cache import PolicyCache
from .fetch import fetch_html
from .overrides import apply_overrides, load_overrides


def normalize_policy(
    cache: PolicyCache, url: str, max_scope_items: int, overrides_path: Path, refresh: bool = False
):
    if not refresh:
        existing = cache.load_by_url(url)
        if existing:
            ovs = load_overrides(overrides_path)
            existing = apply_overrides(existing, ovs) if ovs else existing
            return existing, "cache+overrides" if ovs else "cache"

    html_path = cache.html_path(url)
    if html_path.exists() and not refresh:
        html = html_path.read_text(encoding="utf-8")
        source = "cache"
    else:
        html = fetch_html(url, html_path)
        source = "network"
    fetched_at_utc = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    reg = AdapterRegistry()
    reg.register(GenericAdapter())
    adapter = reg.pick(url) or GenericAdapter()

    pol = adapter.normalize(url, html, fetched_at_utc, html_path.as_posix())

    ovs = load_overrides(overrides_path)
    if ovs:
        pol = apply_overrides(pol, ovs)

    cache.save(pol)
    return pol, "fresh+overrides" if ovs else "fresh"
