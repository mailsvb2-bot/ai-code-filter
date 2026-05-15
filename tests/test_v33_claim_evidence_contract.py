import json
from pathlib import Path

from ai_code_filter.claim_evidence_contract import (
    claim_evidence_contract_suite_summary,
    run_claim_evidence_contract_suite,
    validate_claim_evidence_document,
)
from ai_code_filter.cli import main


def categories(report):
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def valid_doc():
    return {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": 1,
        "audit_provenance": {
            "claim_boundary": "Items separate tool, external and regression fixture origins.",
            "automated_tool_found_all": False,
        },
        "claim_summary": {"by_source": {"external_adversarial_audit": 1}, "total_count": 1},
        "verification_commands": [
            {"command": "python -m pytest -q", "status": "passed", "exit_code": 0, "artifact": "pytest.log"}
        ],
        "fixes": [
            {
                "id": "FIX-001",
                "title": "External audit found encoded separator blind spot",
                "classification": "blind_spot",
                "status": "fixed",
                "before_version": "0.32.0",
                "after_version": "0.38.0",
                "regression_test": True,
                "test_path": "tests/test_claim_evidence_contract.py::test_encoded_separator",
                "evidence_type": "manual_review",
                "threat_model_gap": "external audit discovered an unmodeled encoded separator bypass",
                "source": {
                    "method": "external_adversarial_audit",
                    "reviewer": "external_acceptance",
                    "review_date": "2026-05-13",
                    "evidence": ["tests/test_claim_evidence_contract.py::test_encoded_separator"],
                },
            }
        ],
    }


def test_claim_evidence_valid_doc_passes():
    assert not validate_claim_evidence_document(valid_doc()).issues


def test_claim_evidence_summary_and_command_contracts():
    doc = valid_doc()
    doc["claim_summary"] = {"by_source": {"external_adversarial_audit": 99}, "total_count": 1}
    assert "EVID004" in categories(validate_claim_evidence_document(doc))
    doc = valid_doc()
    doc["verification_commands"] = [{"command": "pytest", "status": "passed", "exit_code": 1, "artifact": "pytest.log"}]
    assert "EVID011" in categories(validate_claim_evidence_document(doc))


def test_claim_evidence_item_contracts():
    doc = valid_doc()
    doc["fixes"][0]["evidence_type"] = None
    assert "EVID014" in categories(validate_claim_evidence_document(doc))
    doc = valid_doc()
    doc["fixes"][0]["source"].pop("review_date")
    assert "EVID018" in categories(validate_claim_evidence_document(doc))
    doc = valid_doc()
    doc["fixes"][0]["test_path"] = ""
    assert "EVID021" in categories(validate_claim_evidence_document(doc))


def test_claim_evidence_suite_passes_and_has_inventory():
    assert not run_claim_evidence_contract_suite().issues
    summary = claim_evidence_contract_suite_summary()
    assert summary["case_count"] >= 10
    assert "document_summary" in summary["threat_classes"]


def test_claim_evidence_cli_validation(tmp_path):
    path = tmp_path / "fixes.json"
    path.write_text(json.dumps(valid_doc()), encoding="utf-8")
    out = tmp_path / "nested" / "claim.json"
    assert main(["validate-claim-evidence", str(path), "--output", str(out), "--ci"]) == 0
    assert out.exists()
    bad = valid_doc()
    bad["claim_summary"] = {"by_source": {"external_adversarial_audit": 99}, "total_count": 1}
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert main(["validate-claim-evidence", str(path), "--ci"]) == 1
