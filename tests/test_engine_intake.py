import json
import copy
from pathlib import Path

from bounty_hive.intake.engine import ingest_engine_disclosure


def load_engine_fixture() -> dict:
    """
    Load a real Engine-produced disclosure package.
    This is the canonical trust-chain test.
    """
    path = Path("/tmp/proof.json")
    if not path.exists():
        raise RuntimeError(
            "Expected /tmp/proof.json. "
            "Run Engine proof_bundle first."
        )
    return json.loads(path.read_text())


def test_core_accepts_valid_engine_package():
    pkg = load_engine_fixture()
    ingest_engine_disclosure(pkg)  # should not raise


def test_core_rejects_tampered_package():
    pkg = load_engine_fixture()
    tampered = copy.deepcopy(pkg)
    tampered["summary"] = "tampered"

    try:
        ingest_engine_disclosure(tampered)
        assert False, "Expected tampered package to be rejected"
    except Exception as e:
        assert "hash" in str(e).lower() or "canonical" in str(e).lower()
