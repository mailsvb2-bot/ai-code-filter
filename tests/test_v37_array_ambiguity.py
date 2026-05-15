from pathlib import Path

from ai_code_filter.array_ambiguity import array_ambiguity_suite_summary, run_array_ambiguity_suite
from ai_code_filter.analyzers.array_ambiguity import ArrayAmbiguityAnalyzer
from ai_code_filter.models import FilePayload


def _payload(tmp_path: Path, name: str, source: str) -> FilePayload:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return FilePayload(path=path, project_root=tmp_path, content=source)


def test_array_ambiguity_suite_passes():
    report = run_array_ambiguity_suite()
    assert not report.issues
    assert not report.failed_files
    assert not report.skipped_files


def test_array_ambiguity_summary_has_cases():
    summary = array_ambiguity_suite_summary()
    assert summary["suite"] == "array_ambiguity"
    assert summary["case_count"] >= 10
    assert "policy_conflicts" in summary["by_family"]


def test_python_duplicate_route_detected(tmp_path):
    payload = _payload(tmp_path, "routes.py", "routes = [{'route': '/x'}, {'route': '/x'}]\n")
    issues = ArrayAmbiguityAnalyzer().analyze(payload)
    assert any(issue.category.startswith("ARR003") for issue in issues)


def test_python_allow_deny_detected(tmp_path):
    payload = _payload(tmp_path, "policy.py", "policies = [{'subject':'u','action':'read','resource':'r','effect':'allow'}, {'subject':'u','action':'read','resource':'r','effect':'deny'}]\n")
    issues = ArrayAmbiguityAnalyzer().analyze(payload)
    assert any(issue.category.startswith("ARR004") for issue in issues)


def test_valid_unique_arrays_do_not_trigger(tmp_path):
    payload = _payload(tmp_path, "ok.py", "routes = [{'route': '/a'}, {'route': '/b'}]\nroles = ['admin', 'user']\n")
    issues = ArrayAmbiguityAnalyzer().analyze(payload)
    assert not issues
