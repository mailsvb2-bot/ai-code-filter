from __future__ import annotations

from ai_code_filter.evidence_artifact_safety import (
    evidence_artifact_safety_suite_summary,
    run_evidence_artifact_safety_suite,
    validate_evidence_artifact_safety_document,
)


def categories(report):
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def valid_doc(**overrides):
    item = {
        "id": "EAS-T1",
        "title": "Valid evidence safety record",
        "classification": "hardening_gap",
        "status": "fixed",
        "before_version": "0.35.0",
        "after_version": "0.38.0",
        "regression_test": True,
        "test_path": "tests/test_v38_evidence_artifact_safety.py",
        "evidence_type": "manual_review",
        "threat_model_gap": "Evidence references need local safe paths.",
        "source": {
            "method": "external_adversarial_audit",
            "reviewer": "external_acceptance",
            "review_date": "2026-05-14",
            "evidence": ["tests/test_v38_evidence_artifact_safety.py::test_suite_is_clean"],
        },
    }
    item.update(overrides.pop("item_overrides", {}))
    if "source_overrides" in overrides:
        item["source"].update(overrides.pop("source_overrides"))
    data = {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": 1,
        "audit_provenance": {"claim_boundary": "This report separates tool and external claim sources.", "automated_tool_found_all": False},
        "claim_summary": {"by_source": {item["source"]["method"]: 1}, "total_count": 1},
        "verification_commands": [{"command": "python -m pytest -q", "status": "passed", "exit_code": 0, "artifact": "artifacts/pytest.log"}],
        "fixes": [item],
    }
    data.update(overrides)
    return data


def test_suite_is_clean():
    report = run_evidence_artifact_safety_suite()
    assert not report.issues
    assert evidence_artifact_safety_suite_summary()["case_count"] >= 30


def test_unsafe_evidence_and_artifact_paths_are_rejected():
    doc = valid_doc(source_overrides={"evidence": ["../secret.txt"]})
    assert "EAS002" in categories(validate_evidence_artifact_safety_document(doc))
    doc = valid_doc(verification_commands=[{"command": "python -m pytest -q", "status": "passed", "exit_code": 0, "artifact": "C:/secret.txt"}])
    assert "EAS007" in categories(validate_evidence_artifact_safety_document(doc))


def test_command_injection_and_duplicate_normalization_are_rejected():
    doc = valid_doc(verification_commands=[{"command": "pytest -q && rm -rf /", "status": "passed", "exit_code": 0, "artifact": "pytest.log"}])
    assert "EAS013" in categories(validate_evidence_artifact_safety_document(doc))
    doc = valid_doc(verification_commands=[{"command":"pytest -q","status":"passed","exit_code":0,"artifact":"a.log"},{"command":"pytest -q ","status":"passed","exit_code":0,"artifact":"b.log"}])
    cats = categories(validate_evidence_artifact_safety_document(doc))
    assert "EAS014" in cats or "EAS015" in cats


def test_reviewer_version_status_policy_is_rejected():
    assert "EAS016" in categories(validate_evidence_artifact_safety_document(valid_doc(source_overrides={"method": "human_review", "reviewer": "unknown"})))
    assert "EAS018" in categories(validate_evidence_artifact_safety_document(valid_doc(source_overrides={"method": "human_review", "reviewer": "external", "review_date": "2999-01-01"})))
    assert "EAS024" in categories(validate_evidence_artifact_safety_document(valid_doc(item_overrides={"before_version": "00.35.0"})))
    assert "EAS027" in categories(validate_evidence_artifact_safety_document(valid_doc(item_overrides={"status": "detected"})))


def test_valid_document_has_no_eas_issues():
    report = validate_evidence_artifact_safety_document(valid_doc())
    assert not [issue for issue in report.issues if issue.detector == "evidence_artifact_safety"]
