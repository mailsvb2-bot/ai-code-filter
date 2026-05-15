import json
from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.provenance_honesty import validate_provenance_document


def valid_doc(item_overrides=None, source_overrides=None, **doc_overrides):
    source = {
        "method": "external_adversarial_audit",
        "reviewer": "external_acceptance",
        "evidence": ["tests/test_regression.py::test_case"],
    }
    if source_overrides:
        source.update(source_overrides)
    item = {
        "id": "FIX-001",
        "title": "External audit found release hardening gap",
        "classification": "hardening_gap",
        "status": "fixed",
        "before_version": "0.31.0",
        "after_version": "0.38.0",
        "regression_test": True,
        "source": source,
    }
    if item_overrides:
        item.update(item_overrides)
    doc = {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": 1,
        "audit_provenance": {
            "claim_boundary": "External audit sources are separated from tool self-scan claims.",
            "automated_tool_found_all": False,
        },
        "fixes": [item],
    }
    doc.update(doc_overrides)
    return doc


def categories(doc):
    return {issue.category.split(':', 1)[0] for issue in validate_provenance_document(doc).issues}


def test_v32_valid_provenance_still_passes():
    assert not validate_provenance_document(valid_doc()).issues


def test_v32_schema_version_required_and_supported():
    assert "PROV021" in categories(valid_doc(schema_version=None))
    assert "PROV022" in categories(valid_doc(schema_version="2.0"))


def test_v32_claim_boundary_must_explain_source_separation_and_boolean_flag():
    assert "PROV023" in categories(valid_doc(audit_provenance={"claim_boundary": "fixed", "automated_tool_found_all": False}))
    assert "PROV024" in categories(valid_doc(audit_provenance={"claim_boundary": "source boundary", "automated_tool_found_all": "false"}))


def test_v32_rejects_ambiguous_item_containers_and_non_object_items():
    doc = valid_doc(findings=[])
    assert "PROV025" in categories(doc)
    doc = valid_doc(fixes=[valid_doc()["fixes"][0], "not-object"], fixed_count=1)
    assert "PROV027" in categories(doc)


def test_v32_requires_correct_count_field_and_rejects_bad_counts():
    assert "PROV029" in categories(valid_doc(fixed_count=None))
    assert "PROV006" in categories(valid_doc(fixed_count=True))
    assert "PROV030" in categories(valid_doc(fixed_count=-1))
    assert "PROV028" in categories(valid_doc(finding_count=1))


def test_v32_rejects_duplicate_missing_ids_and_missing_titles():
    base = valid_doc()["fixes"][0]
    assert "PROV032" in categories(valid_doc(fixes=[base, {**base}], fixed_count=2))
    assert "PROV031" in categories(valid_doc(item_overrides={"id": "  "}))
    assert "PROV033" in categories(valid_doc(item_overrides={"title": ""}))


def test_v32_version_boundary_is_strict():
    assert "PROV034" in categories(valid_doc(item_overrides={"before_version": "v31", "after_version": "0.38.0"}))
    assert "PROV035" in categories(valid_doc(item_overrides={"before_version": "0.38.0", "after_version": "0.38.0"}))


def test_v32_evidence_and_command_are_structured():
    assert "PROV036" in categories(valid_doc(source_overrides={"evidence": "tests/test.py"}))
    assert "PROV037" in categories(valid_doc(source_overrides={"command": []}))
    assert "PROV014" in categories(valid_doc(source_overrides={"evidence": [], "command": ""}))


def test_v32_tool_claims_require_command_and_version():
    doc = valid_doc(item_overrides={"classification": "reproduced_defect"}, source_overrides={"method": "tool_self_scan", "command": "ai-code-filter analyze .", "evidence": ["report.json"]})
    assert "PROV038" in categories(doc)
    doc = valid_doc(item_overrides={"classification": "reproduced_defect"}, source_overrides={"method": "tool_self_scan", "tool_version": "0.38.0", "evidence": ["report.json"]})
    assert "PROV015" in categories(doc)


def test_v32_human_and_regression_sources_require_identity_or_evidence():
    assert "PROV016" in categories(valid_doc(source_overrides={"method": "human_review", "reviewer": "   "}))
    assert "PROV039" in categories(valid_doc(item_overrides={"classification": "regression_fixture"}, source_overrides={"method": "regression_fixture", "evidence": []}))


def test_v32_broader_tool_wording_is_caught():
    assert "PROV018" in categories(valid_doc(item_overrides={"title": "v29 detected this external gap"}))
    assert "PROV018" in categories(valid_doc(item_overrides={"title": "Detected by ai-code-filter during external review"}))


def test_v32_blindspot_and_hardening_sources_are_not_tool_attributed():
    doc = valid_doc(item_overrides={"classification": "blind_spot"}, source_overrides={"method": "release_audit", "command": "ai-code-filter release-audit .", "tool_version": "0.38.0"})
    cats = categories(doc)
    assert "PROV017" in cats
    assert "PROV040" in cats


def test_v32_fixed_hardening_gap_requires_regression_evidence():
    assert "PROV019" in categories(valid_doc(item_overrides={"regression_test": False}))
    assert "PROV041" in categories(valid_doc(item_overrides={"regression_test": False, "classification": "reproduced_defect"}))


def test_v32_validate_provenance_cli_writes_nested_outputs(tmp_path: Path):
    src = tmp_path / "fixes.json"
    src.write_text(json.dumps(valid_doc(), ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "nested" / "prov.json"
    assert main(["validate-provenance", str(src), "--output", str(out), "--ci"]) == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["TOTAL"] == 0


def test_v32_validate_provenance_cli_fails_on_bad_document(tmp_path: Path):
    src = tmp_path / "bad.json"
    src.write_text(json.dumps(valid_doc(fixed_count=2), ensure_ascii=False), encoding="utf-8")
    assert main(["validate-provenance", str(src), "--ci"]) == 1
