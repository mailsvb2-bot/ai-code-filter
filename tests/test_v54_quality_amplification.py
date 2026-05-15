from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ai_code_filter.precision_audit import audit_precision_corpus
from ai_code_filter.quality_matrix import audit_quality_matrix
from ai_code_filter.stress_audit import audit_stress


def test_precision_audit_accepts_clean_and_expected_cases(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    clean = corpus / "clean"
    clean.mkdir(parents=True)
    (clean / "ok.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    (corpus / "bad.py").write_text("import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    (corpus / "expected.json").write_text(json.dumps({"cases": [{"path": "bad.py", "must_find": ["shell"]}]}), encoding="utf-8")

    report, summary = audit_precision_corpus(corpus)

    assert report.summary()["TOTAL"] == 0
    assert summary.clean_cases == 1
    assert summary.expected_cases == 1
    assert summary.expected_matches == 1


def test_precision_audit_flags_expected_case_drift(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "expected.json").write_text(json.dumps({"cases": [{"path": "safe.py", "must_find": ["definitely_missing"]}]}), encoding="utf-8")
    (corpus / "safe.py").write_text("def safe() -> int:\n    return 1\n", encoding="utf-8")

    report, _summary = audit_precision_corpus(corpus)

    assert any("expected finding not detected" in issue.category for issue in report.issues)


def test_stress_audit_reports_metrics_without_blockers() -> None:
    report, summary = audit_stress(files=12, max_seconds=20, max_unknown_ratio=1.0)

    assert report.summary()["TOTAL"] == 0
    assert summary.files == 12
    assert summary.graph_nodes > 0
    assert summary.files_per_second > 0


def test_quality_matrix_runs_core_gates_on_current_project() -> None:
    report, summary = audit_quality_matrix(Path("."))

    assert summary.gates_run >= 7
    assert summary.gates_with_blockers == 0
    assert report.summary()["TOTAL"] == 0


def test_v54_cli_commands_are_registered(tmp_path: Path) -> None:
    proc = subprocess.run([sys.executable, "ai_filter.py", "--help"], text=True, capture_output=True, check=True)
    assert "precision-audit" in proc.stdout
    assert "stress-audit" in proc.stdout
    assert "quality-matrix" in proc.stdout
