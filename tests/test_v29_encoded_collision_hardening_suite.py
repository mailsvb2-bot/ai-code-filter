from __future__ import annotations

from ai_code_filter.encoded_collision_hardening import (
    encoded_collision_hardening_suite_summary,
    run_encoded_collision_hardening_suite,
)


def test_encoded_collision_hardening_suite_passes() -> None:
    report = run_encoded_collision_hardening_suite()
    assert not report.issues
    assert not report.failed_files
    assert not report.skipped_files


def test_encoded_collision_hardening_suite_inventory() -> None:
    summary = encoded_collision_hardening_suite_summary()
    assert summary["case_count"] >= 18
    threat_classes = set(summary["threat_classes"])
    assert "percent_encoded_and_double_encoded_path_separators" in threat_classes
    assert "manifest_case_and_unicode_normalized_collisions" in threat_classes
    assert "yaml_ini_duplicate_keys" in threat_classes
