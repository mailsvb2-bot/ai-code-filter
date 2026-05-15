import json
from pathlib import Path

from ai_code_filter.claim_evidence_contract import (
    claim_evidence_contract_suite_summary,
    validate_claim_evidence_document,
)
from ai_code_filter.provenance_honesty import validate_provenance_document


def categories(report):
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def valid_doc(item_overrides=None, source_overrides=None, summary_overrides=None, commands=None):
    item = {
        "id": "FIX-001",
        "title": "External audit reproduced claim-evidence gap",
        "classification": "blind_spot",
        "status": "fixed",
        "before_version": "0.33.0",
        "after_version": "0.38.0",
        "regression_test": True,
        "test_path": "tests/test_v34_claim_evidence_external_audit.py::test_case",
        "evidence_type": "manual_review",
        "threat_model_gap": "external audit found a claim evidence contract blind spot",
        "source": {
            "method": "external_adversarial_audit",
            "reviewer": "assistant_external_acceptance",
            "review_date": "2026-05-13",
            "evidence": ["tests/test_v34_claim_evidence_external_audit.py"],
        },
    }
    if source_overrides:
        item["source"].update(source_overrides)
    if item_overrides:
        item.update(item_overrides)
    by_source = {item["source"]["method"]: 1}
    summary = {"by_source": by_source, "total_count": 1}
    if summary_overrides is not None:
        summary = summary_overrides
    return {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": 1,
        "audit_provenance": {
            "claim_boundary": "Items separate tool, external and regression fixture origins.",
            "automated_tool_found_all": False,
        },
        "claim_summary": summary,
        "verification_commands": commands or [
            {"command": "python -m pytest -q", "status": "passed", "exit_code": 0, "artifact": "pytest.log"}
        ],
        "fixes": [item],
    }


def test_summary_counts_are_strict_integers_and_supported_methods():
    assert "EVID025" in categories(validate_claim_evidence_document(valid_doc(summary_overrides={"by_source": {"external_adversarial_audit": True}, "total_count": 1})))
    assert "EVID026" in categories(validate_claim_evidence_document(valid_doc(summary_overrides={"by_source": {"external_adversarial_audit": -1}, "total_count": 1})))
    assert "EVID024" in categories(validate_claim_evidence_document(valid_doc(summary_overrides={"by_source": {"mystery": 1}, "total_count": 1})))
    assert "EVID027" in categories(validate_claim_evidence_document(valid_doc(summary_overrides={"by_source": {"external_adversarial_audit": 1}})))
    assert "EVID028" in categories(validate_claim_evidence_document(valid_doc(summary_overrides={"by_source": {"external_adversarial_audit": 1}, "total_count": 2})))


def test_verification_commands_are_not_ambiguous():
    assert "EVID029" in categories(validate_claim_evidence_document(valid_doc(commands=[
        {"command": "pytest", "status": "passed", "exit_code": 0, "artifact": "a.log"},
        {"command": "pytest", "status": "passed", "exit_code": 0, "artifact": "b.log"},
    ])))
    assert "EVID031" in categories(validate_claim_evidence_document(valid_doc(commands=[
        {"command": "pyright", "status": "skipped", "exit_code": 0, "artifact": "type.json"},
    ])))
    assert "EVID030" in categories(validate_claim_evidence_document(valid_doc(commands=[
        {"command": "pyright", "status": "skipped", "exit_code": 1, "artifact": "type.json", "skip_reason": "missing"},
    ])))


def test_tool_and_suite_claims_require_semver_tool_version():
    tool_item = {
        "classification": "reproduced_defect",
        "evidence_type": "artifact_report",
        "reproduction": {"command": "x", "observed_before": "bad", "verified_after": "good"},
    }
    assert "EVID032" in categories(validate_claim_evidence_document(valid_doc(item_overrides=tool_item, source_overrides={"method": "adversarial_suite", "command": "ai-code-filter adversarial-suite", "evidence": ["a.json"]}, summary_overrides={"by_source": {"adversarial_suite": 1}, "total_count": 1})))
    assert "EVID033" in categories(validate_claim_evidence_document(valid_doc(item_overrides=tool_item, source_overrides={"method": "adversarial_suite", "command": "ai-code-filter adversarial-suite", "tool_version": "latest", "evidence": ["a.json"]}, summary_overrides={"by_source": {"adversarial_suite": 1}, "total_count": 1})))


def test_external_dates_regression_fixtures_and_versions_are_strict():
    assert "EVID018" in categories(validate_claim_evidence_document(valid_doc(source_overrides={"review_date": "2026-99-99"})))
    assert "EVID034" in categories(validate_claim_evidence_document(valid_doc(item_overrides={"evidence_type": "manual_review"}, source_overrides={"method": "regression_fixture", "evidence": ["tests/x.py"]}, summary_overrides={"by_source": {"regression_fixture": 1}, "total_count": 1})))
    assert "EVID035" in categories(validate_claim_evidence_document(valid_doc(item_overrides={"evidence_type": "regression_test", "regression_test": False}, source_overrides={"method": "regression_fixture", "evidence": ["tests/x.py"]}, summary_overrides={"by_source": {"regression_fixture": 1}, "total_count": 1})))
    assert "EVID036" in categories(validate_claim_evidence_document(valid_doc(item_overrides={"before_version": "0.38.0", "after_version": "0.33.0"})))
    assert "PROV042" in categories(validate_provenance_document(valid_doc(item_overrides={"before_version": "0.38.0", "after_version": "0.33.0"})))


def test_claim_evidence_contract_suite_summary_has_unique_case_ids():
    summary = claim_evidence_contract_suite_summary()
    ids = [case["case_id"] for case in summary["cases"]]
    assert len(ids) == len(set(ids))
    assert summary["case_count"] >= 24
