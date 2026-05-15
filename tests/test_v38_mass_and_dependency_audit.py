from pathlib import Path

from ai_code_filter.dependency_audit import run_dependency_audit
from ai_code_filter.mass_audit import mass_audit_summary, run_mass_audit


def test_mass_audit_current_project_is_clean():
    report = run_mass_audit(Path('.'), strict=True)
    assert not report.has_blocking_issues()
    summary = mass_audit_summary(Path('.'))
    assert summary["python_file_count"] > 0


def test_dependency_audit_rejects_mandatory_openai(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\nversion="0.1.0"\ndependencies=["openai>=1"]\n', encoding='utf-8')
    report = run_dependency_audit(tmp_path)
    assert any("OpenAI" in issue.description for issue in report.issues)


def test_dependency_audit_detects_duplicate_conflicts(tmp_path):
    (tmp_path / "requirements.txt").write_text('requests>=2\nrequests<1\n', encoding='utf-8')
    report = run_dependency_audit(tmp_path)
    assert any("Duplicate/conflicting" in issue.description for issue in report.issues)
