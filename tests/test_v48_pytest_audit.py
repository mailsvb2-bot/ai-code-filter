from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ai_code_filter.pytest_audit import audit_pytest


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_pytest_audit_runs_pytest_and_writes_summary(tmp_path: Path):
    _write(tmp_path / "tests" / "test_ok.py", "def test_ok():\n    assert 1 == 1\n")
    report, summary = audit_pytest(tmp_path, timeout=20)
    assert summary is not None
    assert summary.returncode == 0
    assert summary.counts["passed"] >= 1
    assert not report.has_blocking_issues()


def test_pytest_audit_detects_failed_pytest_run(tmp_path: Path):
    _write(tmp_path / "tests" / "test_bad.py", "def test_bad():\n    assert False\n")
    report, summary = audit_pytest(tmp_path, timeout=20)
    assert summary is not None
    assert summary.returncode != 0
    assert any(issue.category.startswith("PYTEST002") for issue in report.issues)
    assert report.has_blocking_issues()


def test_pytest_audit_detects_skip_xfail_without_reason_static_only(tmp_path: Path):
    _write(
        tmp_path / "tests" / "test_masked.py",
        "import pytest\n\n@pytest.mark.skip\ndef test_hidden():\n    assert False\n",
    )
    report, summary = audit_pytest(tmp_path, run=False)
    assert summary is None
    assert any(issue.category.startswith("PYTEST020") for issue in report.issues)


def test_pytest_audit_detects_import_only_and_no_assert(tmp_path: Path):
    _write(tmp_path / "tests" / "test_import_only.py", "import os\nimport sys\n")
    _write(tmp_path / "tests" / "test_decorative.py", "def test_decorative():\n    value = 1 + 1\n")
    report, _summary = audit_pytest(tmp_path, run=False)
    categories = {issue.category for issue in report.issues}
    assert any(category.startswith("PYTEST012") for category in categories)
    assert any(category.startswith("PYTEST021") for category in categories)


def test_pytest_audit_allows_pytest_raises_as_assertion(tmp_path: Path):
    _write(
        tmp_path / "tests" / "test_raises.py",
        "import pytest\n\ndef test_raises():\n    with pytest.raises(ValueError):\n        raise ValueError('x')\n",
    )
    report, _summary = audit_pytest(tmp_path, run=False)
    assert not any(issue.category.startswith("PYTEST021") for issue in report.issues)


def test_pytest_audit_cli_summary_json(tmp_path: Path):
    _write(tmp_path / "tests" / "test_ok.py", "def test_ok():\n    assert True\n")
    summary = tmp_path / "pytest_summary.json"
    result = subprocess.run(
        [sys.executable, "ai_filter.py", "pytest-audit", str(tmp_path), "--timeout", "20", "--summary-json", str(summary), "--ci"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(summary.read_text(encoding="utf-8"))
    assert data["pytest"]["counts"]["passed"] >= 1
