from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.grep_audit import audit_grep_patterns
from ai_code_filter.compatibility_audit import audit_compatibility
from ai_code_filter.quality_matrix import audit_quality_matrix
from ai_code_filter.cli import main


def test_grep_audit_detects_merge_conflict_marker(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("<<<<<<< HEAD\nprint('bad')\n>>>>>>> branch\n", encoding="utf-8")
    report, summary = audit_grep_patterns(tmp_path)
    assert summary.matches >= 2
    assert any(issue.category == "GREP001: grep.merge_conflict_marker" for issue in report.issues)


def test_grep_audit_detects_configured_forbidden_terms(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "module.py").write_text("PUBLIC_NAME = 'LegacyBrand'\n", encoding="utf-8")
    pattern_file = tmp_path / "patterns.json"
    pattern_file.write_text(json.dumps({"patterns": [{"id": "public.forbidden_name", "regex": "LegacyBrand", "severity": "HIGH", "include": ["src/**/*.py"], "description": "Forbidden public name leaked."}]}), encoding="utf-8")
    report, summary = audit_grep_patterns(tmp_path, pattern_file=pattern_file, include_builtins=False)
    assert summary.patterns == 1
    assert summary.matches == 1
    assert report.issues[0].category == "GREP001: public.forbidden_name"
    assert report.issues[0].line_number == 1


def test_grep_audit_cli_outputs_summary(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("-----BEGIN " + "PRIVATE KEY-----\n", encoding="utf-8")
    summary = tmp_path / "summary.json"
    assert main(["grep-audit", str(tmp_path), "--summary-json", str(summary), "--ci"]) == 1
    data = json.loads(summary.read_text(encoding="utf-8"))
    assert data["grep_audit"]["matches"] == 1


def test_compatibility_surface_includes_grep_audit() -> None:
    report, summary = audit_compatibility(Path.cwd())
    assert summary.missing_commands == 0
    assert not report.issues


def test_quality_matrix_includes_clean_grep_gate(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "LIMITATIONS.json").write_text("{}", encoding="utf-8")
    report, summary = audit_quality_matrix(tmp_path)
    assert summary.gates_run >= 1
    assert not any(issue.category.startswith("grep_audit:") for issue in report.issues)
