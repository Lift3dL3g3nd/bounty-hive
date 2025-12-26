from __future__ import annotations

from pathlib import Path

from bounty_hive.cache import PolicyCache
from bounty_hive.normalize import normalize_policy


def test_normalize_snapshot(tmp_path: Path):
    cache_dir = tmp_path / ".bounty_hive_cache"
    cache = PolicyCache(cache_dir)
    url = "https://example.local/policy"
    html_path = cache.html_path(url)

    fixture = Path("tests/fixtures/policy_example.html").read_text(encoding="utf-8")
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(fixture, encoding="utf-8")

    pol, src = normalize_policy(
        cache=cache,
        url=url,
        max_scope_items=50,
        overrides_path=Path("policy_overrides.json"),
        refresh=False,
    )
    assert pol.program_title == "Example Program Policy"
    assert any(t.value == "example.com" for t in pol.in_scope)
    assert any(t.value == "*.api.example.com" for t in pol.in_scope)
    assert pol.constraints.prohibits_automated_scanning_language_detected is True
    assert pol.constraints.requires_safe_harbor_language_detected is True
    assert src in {"fresh", "cache", "fresh+overrides", "cache+overrides"}
