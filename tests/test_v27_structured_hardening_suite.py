from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ai_code_filter.structured_hardening import (
    run_structured_hardening_suite,
    structured_hardening_suite_summary,
)

ROOT = Path(__file__).resolve().parents[1]


def test_structured_hardening_suite_passes() -> None:
    report = run_structured_hardening_suite()
    assert not report.issues
    assert not report.failed_files
    assert not report.skipped_files
    summary = structured_hardening_suite_summary()
    assert summary["case_count"] >= 20
    assert "structured_file_parser_hardening" in summary["threat_classes"]
    assert "unicode_slash_and_path_confusables" in summary["threat_classes"]


def test_structured_hardening_cli_outputs_summary(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "structured.json"
    summary = tmp_path / "nested" / "structured_summary.json"
    proc = subprocess.run(
        [sys.executable, "ai_filter.py", "structured-hardening-suite", "--ci", "--output", str(out), "--summary-json", str(summary)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["TOTAL"] == 0
    summary_data = json.loads(summary.read_text(encoding="utf-8"))
    assert summary_data["case_count"] >= 20


def test_release_audit_can_run_structured_hardening_suite(tmp_path: Path) -> None:
    release = tmp_path / "ai_code_filter_refactored_v30"
    pkg = release / "ai_code_filter"
    tests = release / "tests"
    pkg.mkdir(parents=True)
    tests.mkdir()
    (release / "ai_filter.py").write_text("from ai_code_filter.cli import main\nraise SystemExit(main())\n", encoding="utf-8")
    (pkg / "__init__.py").write_text('__version__ = "0.30.0"\n', encoding="utf-8")
    (tests / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
    (release / "README.md").write_text("# Mini Release v30\n", encoding="utf-8")
    (release / "pyproject.toml").write_text(
        '[project]\nname = "mini-release"\nversion = "0.30.0"\ndependencies = []\n[project.scripts]\nai-code-filter = "ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    subprocess.run([sys.executable, "ai_filter.py", "generate-manifest", str(release)], cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = tmp_path / "release.json"
    proc = subprocess.run(
        [
            sys.executable,
            "ai_filter.py",
            "release-audit",
            str(release),
            "--skip-cli-matrix",
            "--structured-hardening-suite",
            "--output",
            str(out),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["TOTAL"] == 0
