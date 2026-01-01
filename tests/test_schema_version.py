from bounty_hive.schema import NORMALIZED_POLICY_SCHEMA_VERSION
from bounty_hive.models import NormalizedPolicy


def test_normalized_policy_has_schema_version():
    pol = NormalizedPolicy(
        program_url="x",
        platform_hint="y",
        program_title="z",
        fetched_at_utc="fetched_at_utc",
        adapter_used="generic",
        source_html_cache_path="/tmp/x.html",
        raw_text_fingerprint="abc",
        rules_excerpt="rules",
        in_scope=[],
        out_of_scope=[],
        constraints=None,  # ok for this test
        requires_human_scope_confirmation=True,
    )
    assert pol.schema_version == NORMALIZED_POLICY_SCHEMA_VERSION
