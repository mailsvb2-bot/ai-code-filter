from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Iterable

from .models import Issue, Report, Severity

_ALLOWED_METHODS = {
    "tool_self_scan",
    "release_audit",
    "adversarial_suite",
    "blindspot_suite",
    "path_portability_suite",
    "structured_hardening_suite",
    "encoded_collision_hardening_suite",
    "provenance_honesty_suite",
    "claim_evidence_contract_suite",
    "claim_summary_verification_suite",
    "evidence_artifact_safety_suite",
    "array_ambiguity_suite",
    "capability_registry",
    "fuzz_suite",
    "mass_audit",
    "dependency_audit",
    "external_adversarial_audit",
    "human_review",
    "regression_fixture",
}
_ALLOWED_CLASSES = {
    "reproduced_defect",
    "blind_spot",
    "regression_fixture",
    "documentation_consistency",
    "policy_gap",
    "hardening_gap",
}
_ALLOWED_STATUS = {"detected", "fixed", "guarded", "verified"}
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_TOOL_METHODS = {
    "tool_self_scan",
    "release_audit",
    "adversarial_suite",
    "blindspot_suite",
    "path_portability_suite",
    "structured_hardening_suite",
    "encoded_collision_hardening_suite",
    "provenance_honesty_suite",
    "claim_evidence_contract_suite",
    "claim_summary_verification_suite",
    "evidence_artifact_safety_suite",
    "array_ambiguity_suite",
    "capability_registry",
    "fuzz_suite",
    "mass_audit",
    "dependency_audit",
}
_WORDING_TOOL_CLAIM_RE = re.compile(
    r"\b(found|detected|reported|discovered)\s+by\s+(?:the\s+)?(?:tool|ai-code-filter|v\d+|v?\d+\.\d+\.\d+)\b"
    r"|\b(?:tool|ai-code-filter|v\d+|v?\d+\.\d+\.\d+)\s+(?:found|detected|reported|discovered)\b",
    re.IGNORECASE,
)
_REQUIRED_COUNT_FIELD = {"fixes": "fixed_count", "audit_findings": "finding_count", "acceptance_report": "item_count"}
_ITEM_LIST_FIELDS = ("fixes", "findings", "items")



@dataclass(frozen=True)
class ProvenanceCase:
    """Regression fixture for audit-claim provenance and wording honesty."""

    case_id: str
    title: str
    family: str
    expected_prefixes: tuple[str, ...]
    payload_factory: Callable[[], dict[str, Any]]


def _issue(rule: str, severity: Severity, description: str, file: str = "<provenance>") -> Issue:
    return Issue(
        file=file,
        category=f"{rule}: Audit provenance honesty",
        severity=severity,
        detector="provenance_honesty",
        description=description,
        recommendation=(
            "Separate tool-detected findings from external audit findings, fixtures and hypotheses; "
            "include reproducible evidence, source method, status and version boundary."
        ),
    )


def _present_item_fields(data: dict[str, Any]) -> list[str]:
    return [field for field in _ITEM_LIST_FIELDS if field in data]


def _as_items(data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[tuple[int, Any]], str | None]:
    present = _present_item_fields(data)
    if len(present) != 1:
        return [], [], present[0] if present else None
    field = present[0]
    raw = data.get(field)
    if not isinstance(raw, list):
        return [], [], field
    items: list[dict[str, Any]] = []
    non_objects: list[tuple[int, Any]] = []
    for idx, item in enumerate(raw, 1):
        if isinstance(item, dict):
            items.append(item)
        else:
            non_objects.append((idx, item))
    return items, non_objects, field


def _is_non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_version(value: Any) -> bool:
    return isinstance(value, str) and bool(_VERSION_RE.match(value.strip()))


def _valid_evidence(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_is_non_empty_str(item) for item in value)


def _valid_command(value: Any) -> bool:
    return _is_non_empty_str(value)


def _version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.strip().split(".")
    return int(major), int(minor), int(patch)


def validate_provenance_document(data: dict[str, Any], *, file: str = "<provenance>") -> Report:
    """Validate audit/fix report provenance so claims cannot conflate source types.

    This validator intentionally does not judge whether a fix is technically correct.
    It checks the honesty contract around *how* a finding was discovered and evidenced.
    """
    report = Report()
    if not isinstance(data, dict):
        report.add(_issue("PROV001", Severity.HIGH, "Provenance document is not a JSON object.", file))
        return report

    artifact_kind = data.get("artifact_kind")
    if artifact_kind not in _REQUIRED_COUNT_FIELD:
        report.add(_issue("PROV002", Severity.HIGH, "Provenance document does not declare a supported artifact_kind.", file))

    schema_version = data.get("schema_version")
    if not _is_non_empty_str(schema_version):
        report.add(_issue("PROV021", Severity.MEDIUM, "Provenance document lacks a non-empty schema_version.", file))
    elif schema_version != "1.0":
        report.add(_issue("PROV022", Severity.MEDIUM, f"Unsupported provenance schema_version: {schema_version!r}.", file))

    audit_provenance = data.get("audit_provenance")
    if not isinstance(audit_provenance, dict):
        report.add(_issue("PROV003", Severity.HIGH, "Document-level audit_provenance is missing or not an object.", file))
    else:
        boundary = audit_provenance.get("claim_boundary")
        if not _is_non_empty_str(boundary):
            report.add(_issue("PROV004", Severity.MEDIUM, "Document-level claim_boundary is missing.", file))
        elif not any(token in boundary.lower() for token in ("tool", "external", "source", "origin", "provenance", "claim")):
            report.add(_issue("PROV023", Severity.MEDIUM, "Document-level claim_boundary does not explain source/provenance separation.", file))
        automated = audit_provenance.get("automated_tool_found_all")
        if not isinstance(automated, bool):
            report.add(_issue("PROV024", Severity.MEDIUM, "automated_tool_found_all must be a boolean.", file))
        elif automated is True:
            report.add(_issue("PROV005", Severity.HIGH, "Document claims all findings were tool-detected; this must be represented per item with evidence.", file))

    present_fields = _present_item_fields(data)
    if len(present_fields) > 1:
        report.add(_issue("PROV025", Severity.HIGH, f"Document has multiple item containers: {', '.join(present_fields)}.", file))
    items, non_objects, item_field = _as_items(data)
    if item_field is None:
        report.add(_issue("PROV026", Severity.HIGH, "Document lacks exactly one item container: fixes, findings or items.", file))
    for idx, value in non_objects:
        report.add(_issue("PROV027", Severity.HIGH, f"Item container entry #{idx} is not an object: {type(value).__name__}.", file))

    if artifact_kind in _REQUIRED_COUNT_FIELD:
        expected_field = _REQUIRED_COUNT_FIELD[artifact_kind]
        declared_count = data.get(expected_field)
        wrong_count_fields = sorted(set(_REQUIRED_COUNT_FIELD.values()) - {expected_field} & set(data.keys()))
        if wrong_count_fields:
            report.add(_issue("PROV028", Severity.MEDIUM, f"artifact_kind={artifact_kind!r} uses unexpected count fields: {', '.join(wrong_count_fields)}.", file))
        if declared_count is None:
            report.add(_issue("PROV029", Severity.HIGH, f"artifact_kind={artifact_kind!r} requires {expected_field}.", file))
        elif isinstance(declared_count, bool) or not isinstance(declared_count, int):
            report.add(_issue("PROV006", Severity.MEDIUM, "Declared finding/fix count is not an integer.", file))
        elif declared_count < 0:
            report.add(_issue("PROV030", Severity.HIGH, "Declared finding/fix count is negative.", file))
        elif declared_count != len(items):
            report.add(_issue("PROV007", Severity.HIGH, f"Declared count {declared_count} does not match item count {len(items)}.", file))

    if not items:
        report.add(_issue("PROV008", Severity.MEDIUM, "Document has no machine-readable fixes/findings/items list.", file))
        return report

    seen_ids: dict[str, int] = {}
    for idx, item in enumerate(items, 1):
        raw_id = item.get("id") or item.get("case_id")
        label = str(raw_id or idx)
        if not _is_non_empty_str(raw_id):
            report.add(_issue("PROV031", Severity.MEDIUM, f"Item #{idx} lacks a non-empty id/case_id.", file))
        else:
            item_id = raw_id.strip()
            if item_id in seen_ids:
                report.add(_issue("PROV032", Severity.HIGH, f"Duplicate item id: {item_id}.", file))
            seen_ids[item_id] = idx
        if not _is_non_empty_str(item.get("title")):
            report.add(_issue("PROV033", Severity.MEDIUM, f"Item {label} lacks a non-empty title.", file))
        source = item.get("source")
        if not isinstance(source, dict):
            report.add(_issue("PROV009", Severity.HIGH, f"Item {label} lacks a structured source object.", file))
            continue
        method = source.get("method")
        if method not in _ALLOWED_METHODS:
            report.add(_issue("PROV010", Severity.HIGH, f"Item {label} has unsupported or missing source.method: {method!r}.", file))
        classification = item.get("classification")
        if classification not in _ALLOWED_CLASSES:
            report.add(_issue("PROV011", Severity.MEDIUM, f"Item {label} lacks a supported classification.", file))
        status = item.get("status")
        if status not in _ALLOWED_STATUS:
            report.add(_issue("PROV012", Severity.MEDIUM, f"Item {label} lacks a supported status.", file))
        before_version = item.get("before_version")
        after_version = item.get("after_version")
        if not before_version or not after_version:
            report.add(_issue("PROV013", Severity.MEDIUM, f"Item {label} lacks before_version/after_version boundary.", file))
        elif not _valid_version(before_version) or not _valid_version(after_version):
            report.add(_issue("PROV034", Severity.MEDIUM, f"Item {label} has invalid before_version/after_version format.", file))
        elif before_version.strip() == after_version.strip():
            report.add(_issue("PROV035", Severity.HIGH, f"Item {label} has identical before_version and after_version.", file))
        elif _version_tuple(after_version) <= _version_tuple(before_version):
            report.add(_issue("PROV042", Severity.HIGH, f"Item {label} has non-increasing version boundary: {before_version} -> {after_version}.", file))
        evidence = source.get("evidence")
        command = source.get("command")
        evidence_ok = _valid_evidence(evidence)
        command_ok = _valid_command(command)
        if evidence is not None and not evidence_ok:
            report.add(_issue("PROV036", Severity.HIGH, f"Item {label} has malformed source.evidence; expected non-empty list of strings.", file))
        if command is not None and not command_ok:
            report.add(_issue("PROV037", Severity.HIGH, f"Item {label} has malformed source.command; expected non-empty string.", file))
        if not evidence_ok and not command_ok:
            report.add(_issue("PROV014", Severity.HIGH, f"Item {label} lacks reproducible evidence or command.", file))
        if method in {"tool_self_scan", "release_audit"} and not command_ok:
            report.add(_issue("PROV015", Severity.HIGH, f"Item {label} claims automated tool discovery without the exact command.", file))
        if method in _TOOL_METHODS:
            tool_version = source.get("tool_version")
            if not _is_non_empty_str(tool_version):
                report.add(_issue("PROV038", Severity.MEDIUM, f"Item {label} claims tool/suite discovery without source.tool_version.", file))
            elif not _valid_version(tool_version):
                report.add(_issue("PROV043", Severity.MEDIUM, f"Item {label} has invalid source.tool_version format.", file))
        if method in {"external_adversarial_audit", "human_review"} and not _is_non_empty_str(source.get("reviewer")):
            report.add(_issue("PROV016", Severity.MEDIUM, f"Item {label} claims external/human audit discovery without reviewer/source identity.", file))
        if method == "regression_fixture" and not evidence_ok:
            report.add(_issue("PROV039", Severity.MEDIUM, f"Item {label} claims regression_fixture without test evidence.", file))
        if classification == "blind_spot" and method in {"tool_self_scan", "release_audit"}:
            report.add(_issue("PROV017", Severity.HIGH, f"Item {label} is a blind spot but is attributed to the tool that missed it.", file))
        text = " ".join(str(item.get(key, "")) for key in ("title", "description", "summary"))
        if _WORDING_TOOL_CLAIM_RE.search(text) and method not in {"tool_self_scan", "release_audit"}:
            report.add(_issue("PROV018", Severity.HIGH, f"Item {label} wording implies tool discovery but source.method={method!r}.", file))
        if item.get("regression_test") is not True and classification in {"blind_spot", "hardening_gap"}:
            report.add(_issue("PROV019", Severity.MEDIUM, f"Item {label} is a blind spot/hardening gap without regression_test=true.", file))
        if classification in {"blind_spot", "hardening_gap"} and method not in {"external_adversarial_audit", "human_review", "regression_fixture"}:
            report.add(_issue("PROV040", Severity.HIGH, f"Item {label} is a blind spot/hardening gap but source.method={method!r} is not an external/regression source.", file))
        if status == "fixed" and item.get("regression_test") is not True and classification != "documentation_consistency":
            report.add(_issue("PROV041", Severity.MEDIUM, f"Fixed item {label} lacks regression evidence.", file))
    return report


def validate_provenance_file(path: Path) -> Report:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive CLI path
        report = Report()
        report.add(_issue("PROV020", Severity.HIGH, f"Could not parse provenance JSON: {type(exc).__name__}: {exc}", str(path)))
        return report
    return validate_provenance_document(data, file=str(path))


def _categories(report: Report) -> set[str]:
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def _has_expected(report: Report, prefixes: tuple[str, ...]) -> bool:
    categories = _categories(report)
    return any(any(category.startswith(prefix) for category in categories) for prefix in prefixes)


def _suite_issue(case: ProvenanceCase, observed: Iterable[str]) -> Issue:
    observed_s = ", ".join(sorted(observed)) or "<none>"
    expected_s = ", ".join(case.expected_prefixes)
    return Issue(
        file=f"<provenance-honesty:{case.case_id}>",
        category="PROVSUITE001: Provenance honesty regression failure",
        severity=Severity.HIGH,
        detector="provenance_honesty_suite",
        description=f"Provenance fixture was not detected: {case.title}. Expected [{expected_s}], observed [{observed_s}].",
        recommendation="Repair provenance/claim-honesty validation and keep this fixture enabled.",
    )


def _ok_issue(case_id: str, title: str) -> Issue:
    return Issue(
        file=f"<provenance-honesty:{case_id}>",
        category="PROV_OK: False-positive guard accepted",
        severity=Severity.LOW,
        detector="provenance_honesty_suite",
        description=title,
        recommendation="No action.",
    )


def _base_item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": "FIX-001",
        "title": "External audit found encoded separator blind spot",
        "classification": "blind_spot",
        "status": "fixed",
        "before_version": "0.30.0",
        "after_version": "0.32.0",
        "regression_test": True,
        "source": {
            "method": "external_adversarial_audit",
            "reviewer": "external_acceptance",
            "evidence": ["tests/test_regression.py::test_encoded_separator"],
        },
    }
    item.update(overrides)
    return item


def _doc(items: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": len(items),
        "audit_provenance": {
            "claim_boundary": "Items are external-audit findings unless explicitly marked as tool_self_scan.",
            "automated_tool_found_all": False,
        },
        "fixes": items,
    }
    data.update(overrides)
    return data


def provenance_honesty_cases() -> list[ProvenanceCase]:
    return [
        ProvenanceCase("missing_artifact_kind", "missing artifact_kind is rejected", "schema", ("PROV002",), lambda: _doc([_base_item()], artifact_kind=None)),
        ProvenanceCase("missing_document_provenance", "missing document audit_provenance is rejected", "document_boundary", ("PROV003",), lambda: {"artifact_kind": "fixes", "fixed_count": 1, "fixes": [_base_item()]}),
        ProvenanceCase("automated_all_claim", "document-level automated_tool_found_all claim is rejected", "claim_boundary", ("PROV005",), lambda: _doc([_base_item()], audit_provenance={"claim_boundary": "x", "automated_tool_found_all": True})),
        ProvenanceCase("count_mismatch", "fixed_count mismatch is rejected", "counts", ("PROV007",), lambda: _doc([_base_item()], fixed_count=27)),
        ProvenanceCase("missing_source", "item without source object is rejected", "item_source", ("PROV009",), lambda: _doc([{k: v for k, v in _base_item().items() if k != "source"}])),
        ProvenanceCase("unsupported_method", "unsupported source.method is rejected", "item_source", ("PROV010",), lambda: _doc([_base_item(source={"method": "magic", "evidence": ["x"]})])),
        ProvenanceCase("missing_classification", "missing classification is rejected", "item_semantics", ("PROV011",), lambda: _doc([_base_item(classification=None)])),
        ProvenanceCase("missing_status", "missing status is rejected", "item_semantics", ("PROV012",), lambda: _doc([_base_item(status=None)])),
        ProvenanceCase("missing_version_boundary", "missing before/after version boundary is rejected", "version_boundary", ("PROV013",), lambda: _doc([_base_item(before_version=None)])),
        ProvenanceCase("missing_evidence", "missing evidence/command is rejected", "evidence", ("PROV014",), lambda: _doc([_base_item(source={"method": "external_adversarial_audit", "reviewer": "x"})])),
        ProvenanceCase("tool_claim_without_command", "tool_self_scan claim without exact command is rejected", "evidence", ("PROV015",), lambda: _doc([_base_item(classification="reproduced_defect", source={"method": "tool_self_scan", "evidence": ["report.json"]})])),
        ProvenanceCase("external_without_reviewer", "external audit source without reviewer is rejected", "evidence", ("PROV016",), lambda: _doc([_base_item(source={"method": "external_adversarial_audit", "evidence": ["x"]})])),
        ProvenanceCase("blindspot_attributed_to_tool", "blind spot cannot be attributed to the tool that missed it", "claim_conflation", ("PROV017",), lambda: _doc([_base_item(source={"method": "tool_self_scan", "command": "ai-code-filter analyze ."})])),
        ProvenanceCase("wording_implies_tool_discovery", "wording that implies tool discovery conflicts with external source", "claim_conflation", ("PROV018",), lambda: _doc([_base_item(title="Found by tool: encoded separator gap")])) ,
        ProvenanceCase("blindspot_without_regression", "blind spot without regression_test=true is rejected", "regression_evidence", ("PROV019",), lambda: _doc([_base_item(regression_test=False)])),
        ProvenanceCase("valid_external_audit_record", "valid external-audit fix record is accepted", "false_positive_guards", ("PROV_OK",), lambda: _doc([_base_item()])),
        ProvenanceCase("valid_tool_self_scan_record", "valid tool-self-scan record is accepted", "false_positive_guards", ("PROV_OK",), lambda: _doc([_base_item(classification="reproduced_defect", source={"method": "tool_self_scan", "command": "ai-code-filter release-audit dist.zip --ci", "tool_version": "0.32.0", "evidence": ["release_audit.json"]})])),
    ]


def run_provenance_honesty_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-provenance-suite-") as tmp_s:
        tmp = Path(tmp_s)
        for case in provenance_honesty_cases():
            payload = case.payload_factory()
            path = tmp / f"{case.case_id}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            observed = validate_provenance_file(path)
            if case.expected_prefixes == ("PROV_OK",):
                if observed.issues:
                    report.extend(observed.issues)
                else:
                    # A low OK issue is used only internally for fixture matching; do not leak as failure.
                    _ok_issue(case.case_id, case.title)
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(_suite_issue(case, _categories(observed)))
    return report


def provenance_honesty_suite_summary() -> dict[str, Any]:
    cases = provenance_honesty_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "suite": "provenance_honesty",
        "case_count": len(cases),
        "threat_classes": sorted(families),
        "by_family": dict(sorted(families.items())),
        "cases": [
            {"case_id": case.case_id, "title": case.title, "family": case.family, "expected_prefixes": list(case.expected_prefixes)}
            for case in cases
        ],
    }
