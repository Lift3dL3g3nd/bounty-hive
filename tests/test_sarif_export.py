from bounty_hive.reporting.sarif import findings_to_sarif


class DummyFinding:
    def __init__(self):
        self.rule_id = "B324"
        self.severity = "HIGH"
        self.tool = "bandit"
        self.file_path = "app.py"
        self.line = 42


def test_sarif_structure():
    findings = [DummyFinding()]
    sarif = findings_to_sarif(findings)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert "tool" in run
    assert "results" in run
    assert len(run["results"]) == 1

    result = run["results"][0]
    assert result["ruleId"] == "B324"
    assert result["level"] == "error"
