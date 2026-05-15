from __future__ import annotations

import json
from datetime import date, timedelta

from ai_code_filter.artifacts import sarif_dict
from ai_code_filter.baseline_contract import audit_baseline
from ai_code_filter.cli import main
from ai_code_filter.config import RuntimeConfig
from ai_code_filter.finding_core import FindingCore
from ai_code_filter.models import Issue, Report, Severity
from ai_code_filter.pipeline import AnalysisPipeline
from ai_code_filter.rule_ownership import audit_rule_ownership, write_default_registry


def test_messaging_profile_detects_token_literal(tmp_path):
    src = tmp_path / "bot.py"
    src.write_text('BOT_TOKEN = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_12345"\n', encoding="utf-8")
    report = AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False, profiles=("messaging-bot",))).analyze_paths([str(tmp_path)])
    assert any(issue.category == "messaging.secret.token_literal" for issue in report.issues)


def test_autonomy_canon_profile_detects_raw_effect_outside_provider(tmp_path):
    src = tmp_path / "runtime" / "router.py"
    src.parent.mkdir()
    src.write_text('import requests\ndef route():\n    return requests.post("https://example.invalid")\n', encoding="utf-8")
    report = AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False, profiles=("autonomy-canon",))).analyze_paths([str(tmp_path)])
    assert any(issue.category == "autonomy_canon.raw_effect.risk" for issue in report.issues)


def test_suppression_requires_reason_owner_expiry_and_unused_is_finding(tmp_path):
    suppression_file = tmp_path / "suppressions.json"
    suppression_file.write_text(json.dumps({"suppressions": [{"rule_id": "missing"}]}), encoding="utf-8")
    core = FindingCore()
    suppressions, errors = core.load_suppressions(suppression_file)
    assert any("reason is required" in error for error in errors)
    assert any("owner is required" in error for error in errors)
    assert any("expires is required" in error for error in errors)

    future = (date.today() + timedelta(days=30)).isoformat()
    suppression_file.write_text(json.dumps({"suppressions": [{"rule_id": "missing", "reason": "stale", "owner": "security", "expires": future}]}), encoding="utf-8")
    suppressions, errors = core.load_suppressions(suppression_file)
    assert errors == []
    report = Report()
    report.add(Issue(file="app.py", category="other.rule", severity=Severity.HIGH, detector="test", description="x"))
    result = core.process(report, suppressions=suppressions)
    assert any(issue.category == "Suppression governance" and "did not match" in issue.description for issue in result.report.issues)


def test_baseline_contract_flags_growth_and_missing_files(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"issues": [{"file": "missing.py", "category": "x", "severity": "HIGH"}]}), encoding="utf-8")
    report = audit_baseline(baseline, project_root=tmp_path, max_issues=0)
    categories = {issue.category for issue in report.issues}
    assert "baseline_contract.growth" in categories
    assert "baseline_contract.missing_file" in categories


def test_sarif_contains_fingerprint_confidence_and_evidence():
    report = Report()
    report.add(Issue(file="app.py", category="python.test", severity=Severity.HIGH, detector="unit", description="bad", confidence="high", evidence={"source": "unit"}))
    result = sarif_dict(report)["runs"][0]["results"][0]
    assert result["partialFingerprints"]["aiCodeFilterFingerprint"]
    assert result["properties"]["confidence"] == "high"
    assert result["properties"]["evidence"] == {"source": "unit"}


def test_rule_ownership_registry_validates_default(tmp_path):
    registry = write_default_registry(tmp_path / "docs" / "RULE_OWNERSHIP.json")
    report = audit_rule_ownership(tmp_path, registry)
    assert report.summary()["TOTAL"] == 0


def test_cli_profile_flag_runs(tmp_path, capsys):
    src = tmp_path / "bot.py"
    src.write_text('BOT_TOKEN = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_12345"\n', encoding="utf-8")
    code = main(["analyze", str(tmp_path), "--no-ai", "--no-drift", "--profile", "messaging-bot", "--ci"])
    assert code == 1
    assert "messaging.secret.token_literal" in capsys.readouterr().out


def test_cli_baseline_audit_and_rule_ownership(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"issues": []}), encoding="utf-8")
    assert main(["baseline-audit", str(baseline), "--ci"]) == 0
    assert main(["rule-ownership", str(tmp_path), "--write-default", "--ci"]) == 0
