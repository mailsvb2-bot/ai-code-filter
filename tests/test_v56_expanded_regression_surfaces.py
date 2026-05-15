from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ai_code_filter.compatibility_audit import audit_compatibility
from ai_code_filter.external_normalization import normalize_external_findings
from ai_code_filter.golden_fixtures import audit_golden_fixtures
from ai_code_filter.ownership_conflicts import audit_ownership_conflicts
from ai_code_filter.profiles import normalize_profiles
from ai_code_filter.zip_fixture_audit import audit_zip_fixtures
from ai_code_filter.cli import main
from ai_code_filter.models import Severity


def test_neutral_profile_names_are_public_contract() -> None:
    assert normalize_profiles(["messaging-bot", "autonomy-canon"]) == ("messaging-bot", "autonomy-canon")


def test_external_normalization_handles_all_requested_tools() -> None:
    ruff = '[{"filename":"app.py","location":{"row":2},"code":"F401","message":"unused import"}]'
    bandit = {"results": [{"filename": "app.py", "line_number": 3, "test_id": "B602", "issue_text": "subprocess shell", "issue_severity": "HIGH", "issue_confidence": "HIGH"}]}
    semgrep = {"results": [{"path": "app.py", "start": {"line": 4}, "check_id": "python.lang.security", "extra": {"severity": "ERROR", "message": "bad"}}]}
    pyright = {"generalDiagnostics": [{"file": "app.py", "range": {"start": {"line": 4}}, "severity": "error", "rule": "reportGeneralTypeIssues", "message": "bad type"}]}
    for tool, payload, prefix in [("ruff", ruff, "external.ruff."), ("bandit", bandit, "external.bandit."), ("semgrep", semgrep, "external.semgrep."), ("pyright", pyright, "external.pyright.")]:
        report, summary = normalize_external_findings(tool, payload)
        assert summary.findings == 1
        assert report.issues[0].category.startswith(prefix)


def test_golden_fixture_expected_categories(tmp_path: Path) -> None:
    (tmp_path / "fx").mkdir()
    (tmp_path / "fx" / "bad.py").write_text('from flask import request, redirect\ndef r():\n    return redirect(request.args.get("next"))\n', encoding="utf-8")
    (tmp_path / "fixtures.json").write_text(json.dumps({"cases": [{"name": "bad", "path": "fx/bad.py", "profiles": ["flask"], "expected_categories": ["flask.open_redirect.risk"]}]}), encoding="utf-8")
    report, summary = audit_golden_fixtures(tmp_path)
    assert summary.cases == 1
    assert summary.matched == 1
    assert not report.issues


def test_zip_fixture_audit_requires_intent_marker(tmp_path: Path) -> None:
    z = tmp_path / "fixture.zip"
    with zipfile.ZipFile(z, "w") as archive:
        archive.writestr("same.txt", "one")
        archive.writestr("same.txt", "two")
    report, summary = audit_zip_fixtures(tmp_path)
    assert summary.unmarked_duplicates == 1
    assert any(issue.category.startswith("ZIPFIX001") for issue in report.issues)
    marker = z.with_suffix(z.suffix + ".intentional-duplicate-zip.json")
    marker.write_text('{"reason":"duplicate-entry parser regression fixture","owner":"tests"}', encoding="utf-8")
    report2, summary2 = audit_zip_fixtures(tmp_path)
    assert summary2.intentional_duplicates == 1
    assert not report2.issues


def test_compatibility_audit_required_command_surface() -> None:
    report, summary = audit_compatibility(Path.cwd())
    assert summary.missing_commands == 0
    assert not report.issues


def test_ownership_conflicts_detects_codeowners_contradiction(tmp_path: Path) -> None:
    (tmp_path / "CODEOWNERS").write_text("src/ @platform\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "module.py").write_text("# owner: @security\n# bypass owner review for emergency\n", encoding="utf-8")
    report, summary = audit_ownership_conflicts(tmp_path)
    cats = {issue.category for issue in report.issues}
    assert "OWN001: conflicting owner markers" in cats
    assert "OWN010: ownership counteraction signal" in cats


def test_new_cli_commands_smoke(tmp_path: Path) -> None:
    payload = tmp_path / "ruff.json"
    payload.write_text('[{"filename":"app.py","location":{"row":2},"code":"F401","message":"unused import"}]', encoding="utf-8")
    assert main(["external-normalize", "--tool", "ruff", "--input", str(payload)]) == 0
