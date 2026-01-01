import re
import inspect
import bounty_hive.reporting.sarif as sarif_module
from bounty_hive.reporting.sarif import findings_to_sarif
from pathlib import Path


class DummyFinding:
    def __init__(self):
        self.rule_id = "TEST001"
        self.severity = "HIGH"
        self.tool = "test-tool"
        self.file_path = "example.py"
        self.line = 10


def test_sarif_is_deterministic():
    findings = [DummyFinding()]

    sarif_1 = findings_to_sarif(findings)
    sarif_2 = findings_to_sarif(findings)

    assert sarif_1 == sarif_2


def test_findings_do_not_include_execution_steps():
    sarif = findings_to_sarif([DummyFinding()])

    results = sarif["runs"][0]["results"]

    for result in results:
        message = result["message"]["text"].lower()

        assert "step" not in message
        assert "exploit" not in message
        assert "run this" not in message


def test_no_network_libraries_used():
    source = inspect.getsource(sarif_module)

    forbidden_imports = [
        "socket",
        "requests",
        "http.client",
        "urllib",
        "asyncio",
    ]

    for lib in forbidden_imports:
        assert lib not in source, f"Network library detected: {lib}"


def test_no_weaponized_content_in_sarif():
    findings = [DummyFinding()]
    sarif = findings_to_sarif(findings)

    sarif_text = str(sarif).lower()

    forbidden_patterns = [
        "shellcode",
        "reverse shell",
        "payload",
        "exec(",
        "subprocess",
        "os.system",
        "curl http",
        "wget http",
        "nc -e",
    ]

    for pattern in forbidden_patterns:
        assert pattern not in sarif_text, f"Forbidden content detected: {pattern}"


def test_trust_contract_exists():
    contract = Path("docs/TRUST_CONTRACT.md")
    assert contract.exists(), "Trust Contract must exist and be committed"
