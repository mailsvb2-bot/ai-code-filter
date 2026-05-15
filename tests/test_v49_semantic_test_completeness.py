from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ai_code_filter.pytest_audit import audit_pytest


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _categories(report):
    return {issue.category for issue in report.issues}


def test_semantic_audit_detects_tests_that_do_not_reference_production(tmp_path: Path):
    _write(tmp_path / "app.py", "def calculate(x):\n    return x + 1\n")
    _write(tmp_path / "tests" / "test_decorative.py", "def test_math():\n    assert 1 == 1\n")
    report, _summary = audit_pytest(tmp_path, run=False, semantic_completeness=True)
    assert any(category.startswith("PYTEST030") for category in _categories(report))
    assert any(category.startswith("PYTEST034") for category in _categories(report))


def test_semantic_audit_allows_referenced_public_symbol_with_real_assertion(tmp_path: Path):
    _write(tmp_path / "app.py", "def calculate(x):\n    return x + 1\n")
    _write(tmp_path / "tests" / "test_app.py", "from app import calculate\n\ndef test_calculate():\n    assert calculate(1) == 2\n")
    report, _summary = audit_pytest(tmp_path, run=False, semantic_completeness=True)
    assert not any(category.startswith("PYTEST030") for category in _categories(report))
    assert not any(category.startswith("PYTEST031") for category in _categories(report))
    assert not any(category.startswith("PYTEST034") for category in _categories(report))


def test_semantic_audit_flags_error_path_without_exception_assertion(tmp_path: Path):
    _write(
        tmp_path / "app.py",
        "def parse(value):\n    if value is None:\n        raise ValueError('missing')\n    return int(value)\n",
    )
    _write(tmp_path / "tests" / "test_app.py", "from app import parse\n\ndef test_parse():\n    assert parse('2') == 2\n")
    report, _summary = audit_pytest(tmp_path, run=False, semantic_completeness=True)
    assert any(category.startswith("PYTEST033") for category in _categories(report))


def test_pytest_audit_cli_semantic_completeness(tmp_path: Path):
    _write(tmp_path / "app.py", "def calculate(x):\n    return x + 1\n")
    _write(tmp_path / "tests" / "test_app.py", "from app import calculate\n\ndef test_calculate():\n    assert calculate(1) == 2\n")
    result = subprocess.run(
        [sys.executable, "ai_filter.py", "pytest-audit", str(tmp_path), "--static-only", "--semantic-completeness", "--ci"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stdout + result.stderr
