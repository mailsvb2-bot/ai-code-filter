from __future__ import annotations

from ai_code_filter.provenance_honesty import (
    provenance_honesty_suite_summary,
    run_provenance_honesty_suite,
    validate_provenance_document,
)


def test_provenance_honesty_suite_passes() -> None:
    report = run_provenance_honesty_suite()
    assert not report.issues
    assert not report.failed_files
    assert not report.skipped_files


def test_provenance_honesty_suite_inventory() -> None:
    summary = provenance_honesty_suite_summary()
    assert summary["case_count"] >= 17
    threat_classes = set(summary["threat_classes"])
    assert "claim_conflation" in threat_classes
    assert "evidence" in threat_classes
    assert "version_boundary" in threat_classes


def test_valid_provenance_document_has_no_issues() -> None:
    data = {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": 1,
        "audit_provenance": {
            "claim_boundary": "External-audit findings are not claimed as tool self-detections.",
            "automated_tool_found_all": False,
        },
        "fixes": [
            {
                "id": "FIX-001",
                "title": "External audit found a manifest parser blind spot",
                "classification": "blind_spot",
                "status": "fixed",
                "before_version": "0.30.0",
                "after_version": "0.38.0",
                "regression_test": True,
                "source": {
                    "method": "external_adversarial_audit",
                    "reviewer": "external_acceptance",
                    "evidence": ["tests/test_v31_provenance_honesty_suite.py"],
                },
            }
        ],
    }
    report = validate_provenance_document(data)
    assert not report.issues


def test_blind_spot_cannot_be_attributed_to_tool_that_missed_it() -> None:
    data = {
        "artifact_kind": "fixes",
        "fixed_count": 1,
        "audit_provenance": {"claim_boundary": "x", "automated_tool_found_all": False},
        "fixes": [
            {
                "id": "FIX-001",
                "title": "Found by tool: hidden blind spot",
                "classification": "blind_spot",
                "status": "fixed",
                "before_version": "0.30.0",
                "after_version": "0.38.0",
                "regression_test": True,
                "source": {"method": "external_adversarial_audit", "reviewer": "x", "evidence": ["manual"]},
            }
        ],
    }
    report = validate_provenance_document(data)
    assert any(issue.category.startswith("PROV018") for issue in report.issues)
