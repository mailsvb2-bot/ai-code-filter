from pathlib import Path
import json

from ai_code_filter.config_contract import audit_config_contract
from ai_code_filter.limitations import limitation_registry
from ai_code_filter.truthfulness import run_truthfulness_gate, validate_limitations_file
from ai_code_filter.cli import main


def test_config_contract_detects_env_drift_and_dangerous_defaults(tmp_path: Path):
    (tmp_path / ".env.example").write_text("BOT_TOKEN=abc123\nSTALE_FLAG=1\nDATABASE_URL=sqlite:///dev.db\n", encoding="utf-8")
    (tmp_path / "app.py").write_text('''
import os
BOT_TOKEN = os.getenv("BOT_TOKEN")
SECRET_KEY = os.environ.get("SECRET_KEY")
''', encoding="utf-8")
    report = audit_config_contract(tmp_path)
    cats = {issue.category.split(":", 1)[0] for issue in report.issues}
    assert {"CFG001", "CFG002", "CFG003", "CFG004"}.issubset(cats)


def test_truthfulness_gate_requires_limitations_for_overclaims(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Complete static analysis production-ready scanner\n", encoding="utf-8")
    report = run_truthfulness_gate(tmp_path)
    assert any(issue.category.startswith("HON001:") for issue in report.issues)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "LIMITATIONS.json").write_text(json.dumps(limitation_registry()), encoding="utf-8")
    assert not run_truthfulness_gate(tmp_path).issues
    assert not validate_limitations_file(tmp_path).has_blocking_issues()


def test_cli_limitations_and_baseline_write(tmp_path: Path, capsys):
    source = tmp_path / "ok.py"
    source.write_text("x = 1\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    assert main(["limitations"]) == 0
    assert "not_a_full_static_analyzer" in capsys.readouterr().out
    assert main(["analyze", str(source), "--no-ai", "--no-drift", "--write-baseline", str(baseline)]) == 0
    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert "issues" in data and "summary" in data

from ai_code_filter.finding_core import FindingCore, FindingPolicy, Suppression
from ai_code_filter.models import Issue, Report, Severity


def test_finding_core_dedupes_and_normalizes_evidence():
    core = FindingCore()
    issue = Issue(
        file="app.py",
        category="SEC001: unsafe call",
        severity=Severity.HIGH,
        detector="unit",
        description="danger",
        confidence="certain",
    )
    report = Report()
    report.add(issue)
    report.add(issue)
    result = core.process(report)
    assert result.duplicate_count == 1
    assert len(result.report.issues) == 1
    normalized = result.report.issues[0]
    assert normalized.confidence == "medium"
    assert normalized.evidence and normalized.evidence["decision_core"] == "FindingCore"


def test_finding_core_applies_suppressions_before_quality_gate():
    core = FindingCore()
    issue = Issue(file="app.py", category="SEC001: unsafe call", severity=Severity.HIGH, detector="unit", description="danger")
    report = Report()
    report.add(issue)
    suppression = Suppression(fingerprint=core.fingerprint(issue), owner="security", reason="accepted test fixture")
    result = core.process(report, policy=FindingPolicy(max_high=0), suppressions=[suppression])
    assert result.suppressed_count == 1
    assert result.report.summary()["HIGH"] == 0
    assert not result.gate_failures
    assert any("suppressed SEC001" in item["reason"] for item in result.report.skipped_files)


def test_finding_core_baseline_gate_uses_single_fingerprint_semantics(tmp_path: Path):
    core = FindingCore()
    issue = Issue(file="app.py", category="SEC001: unsafe call", severity=Severity.HIGH, detector="unit", description="danger")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"issues": [issue.to_dict()]}), encoding="utf-8")
    report = Report()
    report.add(issue)
    assert not core.process(report, policy=FindingPolicy(fail_on_new="HIGH", baseline_report=baseline)).gate_failures
    changed = Report()
    changed.add(Issue(file="app.py", category="SEC001: unsafe call", severity=Severity.HIGH, detector="unit", description="different"))
    assert core.process(changed, policy=FindingPolicy(fail_on_new="HIGH", baseline_report=baseline)).gate_failures
