from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.models import Issue, Report, Severity
from ai_code_filter.policy import QualityGate, apply_suppressions, issue_fingerprint, load_suppressions


def test_issue_fingerprint_is_stable():
    issue = Issue(file="app.py", category="PY002: Security", severity=Severity.CRITICAL, detector="rule_catalog", description="Unsafe eval.", recommendation="Remove eval.", location="eval(x)", line_number=1)
    assert issue_fingerprint(issue) == issue_fingerprint(issue)


def test_quality_gate_blocks_budget():
    report = Report()
    report.add(Issue(file="app.py", category="PY002: Security", severity=Severity.CRITICAL, detector="rule_catalog", description="Unsafe eval.", recommendation="Remove eval."))
    failures = QualityGate(max_critical=0).evaluate(report)
    assert failures and "CRITICAL budget exceeded" in failures[0]


def test_quality_gate_blocks_new_issue_against_baseline(tmp_path: Path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"issues": []}), encoding="utf-8")
    report = Report()
    report.add(Issue(file="app.py", category="PY002: Security", severity=Severity.CRITICAL, detector="rule_catalog", description="Unsafe eval.", recommendation="Remove eval."))
    failures = QualityGate(fail_on_new="HIGH", baseline_report=baseline).evaluate(report)
    assert failures == ["New HIGH+ issues detected: 1"]


def test_suppression_requires_owner_reason_expiry_and_filters(tmp_path: Path):
    issue = Issue(file="app.py", category="PY002: Security", severity=Severity.CRITICAL, detector="rule_catalog", description="Unsafe eval.", recommendation="Remove eval.")
    suppressions_file = tmp_path / "suppressions.json"
    suppressions_file.write_text(json.dumps({"suppressions": [{"rule_id": "PY002", "file": "app.py", "owner": "security", "reason": "accepted in test", "expires": "2999-01-01"}]}), encoding="utf-8")
    suppressions, errors = load_suppressions(suppressions_file)
    assert errors == []
    report = Report(); report.add(issue)
    filtered = apply_suppressions(report, suppressions)
    assert filtered.summary()["TOTAL"] == 0
    assert filtered.summary()["SKIPPED_FILES"] == 1


def test_cli_coverage_matrix_and_plugin_rule(tmp_path: Path):
    coverage = tmp_path / "coverage.json"
    assert main(["list-rules", "--json", str(coverage)]) == 0
    data = json.loads(coverage.read_text(encoding="utf-8"))
    assert data["total_rules"] >= 39

    plugin = tmp_path / "plugin.py"
    plugin.write_text('''\nfrom ai_code_filter.models import Issue, Severity\nfrom ai_code_filter.rules.catalog import Rule\n\ndef register_rules():\n    def check(payload, tree):\n        if "BANME" in payload.content:\n            return [Issue(file=payload.relative_path, category="PL001: Plugin", severity=Severity.HIGH, detector="rule_catalog", description="Plugin marker found.", recommendation="Remove marker.", line_number=1, location="BANME")]\n        return []\n    return [Rule("PL001", "Plugin marker", Severity.HIGH, "text", "Plugin", check, "Plugin smoke test")]\n''', encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("BANME\n", encoding="utf-8")
    report_path = tmp_path / "report.json"
    code = main(["analyze", str(source), "--no-ai", "--no-drift", "--plugin", str(plugin), "--output", str(report_path)])
    assert code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert any(issue["category"].startswith("PL001") for issue in report["issues"])
