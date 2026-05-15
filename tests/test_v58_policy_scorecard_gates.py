from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.ci_profiles import audit_ci_profiles
from ai_code_filter.policy_as_code import audit_policy_as_code
from ai_code_filter.release_evidence import audit_release_evidence
from ai_code_filter.changed_files_audit import audit_changed_files
from ai_code_filter.scorecard import audit_scorecard
from ai_code_filter.cli import main


def _write_min_project(root: Path) -> None:
    (root / "docs").mkdir()
    (root / "README.md").write_text("demo", encoding="utf-8")
    (root / "app.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    compat = {"required_commands": ["analyze", "grep-audit", "policy-audit", "ci-profile-audit", "release-evidence", "scorecard", "changed-files-audit", "quality-matrix", "compatibility-audit", "config-contract"]}
    (root / "docs" / "COMPATIBILITY_REGRESSIONS.json").write_text(json.dumps(compat), encoding="utf-8")
    (root / "docs" / "QUALITY_POLICY.json").write_text(json.dumps({"required_gates": ["analyze", "policy-audit"], "required_artifacts": ["README.md"], "budgets": {"max_high": 0}}), encoding="utf-8")
    (root / "docs" / "CI_PROFILES.json").write_text(json.dumps({"profiles": {"quick": {"strict": True, "commands": ["analyze", "grep-audit"]}, "standard": {"strict": True, "commands": ["quality-matrix", "release-evidence"]}, "release": {"strict": True, "commands": ["scorecard", "policy-audit"]}}}), encoding="utf-8")
    for rel in ["LIMITATIONS.json", "RULE_OWNERSHIP.json", "GREP_AUDIT_PATTERNS.json"]:
        (root / "docs" / rel).write_text("{}", encoding="utf-8")
    entries = ["README.md", "MANIFEST.sha256", "docs/LIMITATIONS.json", "docs/RULE_OWNERSHIP.json", "docs/COMPATIBILITY_REGRESSIONS.json", "docs/QUALITY_POLICY.json", "docs/CI_PROFILES.json", "docs/GREP_AUDIT_PATTERNS.json"]
    (root / "MANIFEST.sha256").write_text("\n".join(f"0  {e}  size=0" for e in entries), encoding="utf-8")


def test_policy_and_ci_profiles_accept_valid_contracts(tmp_path: Path) -> None:
    _write_min_project(tmp_path)
    policy_report, policy_summary = audit_policy_as_code(tmp_path)
    ci_report, ci_summary = audit_ci_profiles(tmp_path)
    assert not policy_report.issues
    assert not ci_report.issues
    assert policy_summary.required_gates == 2
    assert ci_summary.profiles == 3


def test_policy_finds_unprotected_required_gate(tmp_path: Path) -> None:
    _write_min_project(tmp_path)
    (tmp_path / "docs" / "QUALITY_POLICY.json").write_text(json.dumps({"required_gates": ["missing-gate"], "required_artifacts": [], "budgets": {}}), encoding="utf-8")
    report, _ = audit_policy_as_code(tmp_path)
    assert any("POL010" in issue.category for issue in report.issues)


def test_release_evidence_requires_manifest_coverage(tmp_path: Path) -> None:
    _write_min_project(tmp_path)
    (tmp_path / "MANIFEST.sha256").write_text("0  README.md  size=0\n", encoding="utf-8")
    report, summary = audit_release_evidence(tmp_path)
    assert summary.missing_from_manifest > 0
    assert any("REL002" in issue.category for issue in report.issues)


def test_changed_files_audit_rejects_path_traversal(tmp_path: Path) -> None:
    _write_min_project(tmp_path)
    report, _ = audit_changed_files(tmp_path, changed_files=("../escape.py",))
    assert any("CHG003" in issue.category for issue in report.issues)


def test_policy_audit_cli_writes_summary(tmp_path: Path) -> None:
    _write_min_project(tmp_path)
    summary = tmp_path / "policy.json"
    code = main(["policy-audit", str(tmp_path), "--summary-json", str(summary), "--ci"])
    assert code == 0
    assert summary.exists()
