from pathlib import Path


def test_no_root_level_store_directory():
    """
    Guard test:
    The repository must NOT contain a top-level `store/` directory.

    Canonical StoreClient location is:
        bounty_hive/store/client.py
    """
    repo_root = Path(__file__).resolve().parents[1]
    forbidden_path = repo_root / "store"

    assert not forbidden_path.exists(), (
        "Forbidden root-level `store/` directory detected. "
        "Canonical StoreClient must live under `bounty_hive/store/` only."
    )
