from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.blindspots import blindspot_cases, blindspot_suite_summary, run_blindspot_suite
from ai_code_filter.cli import main


def test_blindspot_suite_has_regression_families():
    cases = blindspot_cases()
    families = {case.family for case in cases}
    assert len(cases) >= 23
    assert {
        "manifest_path_parsing",
        "manifest_verification",
        "release_noise",
        "markdown_links",
        "release_metadata",
        "zip_integrity",
    }.issubset(families)


def test_blindspot_suite_passes_when_regressions_are_caught():
    report = run_blindspot_suite()
    assert report.summary()["TOTAL"] == 0
    assert report.summary()["FAILED_FILES"] == 0


def test_blindspot_suite_summary_is_machine_readable():
    summary = blindspot_suite_summary()
    assert summary["case_count"] == len(summary["cases"])
    assert summary["families"]["manifest_path_parsing"] >= 5


def test_blindspot_suite_cli_writes_nested_outputs(tmp_path: Path):
    out = tmp_path / "nested" / "blindspots.json"
    summary = tmp_path / "nested" / "blindspots_summary.json"
    code = main(["blindspot-suite", "--output", str(out), "--summary-json", str(summary), "--ci"])
    assert code == 0
    assert out.exists()
    assert summary.exists()
    assert json.loads(summary.read_text(encoding="utf-8"))["case_count"] >= 23


def test_release_audit_can_include_blindspot_suite(tmp_path: Path):
    out = tmp_path / "nested" / "release.json"
    code = main(["release-audit", ".", "--skip-cli-matrix", "--blindspot-suite", "--output", str(out)])
    assert code == 0
    assert out.exists()
