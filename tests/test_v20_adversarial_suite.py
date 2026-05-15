from __future__ import annotations

from pathlib import Path

from ai_code_filter.adversarial import adversarial_cases, adversarial_suite_summary, run_adversarial_suite
from ai_code_filter.cli import main


def test_adversarial_suite_has_broad_fixture_coverage():
    cases = adversarial_cases()
    assert len(cases) >= 30
    ids = {case.case_id for case in cases}
    assert "zip_traversal" in ids
    assert "release_manifest_tamper" in ids
    assert "tree_markdown_ref_missing_link" in ids


def test_adversarial_suite_passes_when_detectors_catch_fixtures():
    report = run_adversarial_suite()
    assert report.summary()["TOTAL"] == 0
    # Symlink fixtures may be skipped on platforms without symlink support; Linux should not skip.
    assert report.summary()["FAILED_FILES"] == 0


def test_adversarial_summary_is_machine_readable():
    summary = adversarial_suite_summary()
    assert summary["case_count"] >= 30
    assert all("expected_prefixes" in case for case in summary["cases"])


def test_adversarial_suite_cli_writes_nested_outputs(tmp_path: Path):
    out = tmp_path / "nested" / "adversarial.json"
    summary = tmp_path / "nested" / "summary.json"
    code = main(["adversarial-suite", "--output", str(out), "--summary-json", str(summary), "--ci"])
    assert code == 0
    assert out.exists()
    assert summary.exists()


def test_release_audit_can_include_adversarial_suite(tmp_path: Path):
    # Use the source tree as target and skip CLI matrix to keep this focused and fast.
    code = main(["release-audit", ".", "--skip-cli-matrix", "--adversarial-suite", "--output", str(tmp_path / "release.json")])
    assert code == 0
