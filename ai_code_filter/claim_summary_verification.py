
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Iterable

from .claim_evidence_contract import validate_claim_evidence_document, validate_claim_evidence_file
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class ClaimSummaryVerificationCase:
    case_id: str
    title: str
    family: str
    expected_prefixes: tuple[str, ...]
    payload_factory: Callable[[], dict[str, Any]]


def _issue(rule: str, severity: Severity, description: str, file: str = "<claim-summary-verification>") -> Issue:
    return Issue(
        file=file,
        category=f"{rule}: Claim summary and verification command hardening",
        severity=severity,
        detector="claim_summary_verification",
        description=description,
        recommendation=(
            "Keep claim summaries, source counts, verification commands, tool versions and version boundaries "
            "machine-checkable so fixes reports cannot overstate evidence or hide skipped verification."
        ),
    )


def _base_item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": "CSV001",
        "title": "External audit hardening case",
        "classification": "hardening_gap",
        "status": "fixed",
        "before_version": "0.34.0",
        "after_version": "0.38.0",
        "regression_test": True,
        "test_path": "tests/test_claim_summary_verification.py",
        "evidence_type": "manual_review",
        "threat_model_gap": "Claim summary and verification evidence boundaries were under-specified.",
        "source": {
            "method": "external_adversarial_audit",
            "reviewer": "external_acceptance",
            "review_date": "2026-05-14",
            "evidence": ["tests/test_claim_summary_verification.py::test_claim_summary_case"],
        },
    }
    item.update(overrides)
    return item


def _tool_item(**overrides: Any) -> dict[str, Any]:
    item = _base_item(
        classification="reproduced_defect",
        evidence_type="artifact_report",
        source={
            "method": "claim_summary_verification_suite",
            "command": "ai-code-filter claim-summary-verification-suite --ci",
            "tool_version": "0.38.0",
            "evidence": ["claim_summary_verification.json"],
        },
        reproduction={
            "command": "ai-code-filter validate-claim-evidence fixes.json --ci",
            "observed_before": "invalid evidence contract accepted",
            "verified_after": "invalid evidence contract rejected",
        },
    )
    item.update(overrides)
    return item


def _doc(items: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    by_source: dict[str, int] = {}
    for item in items:
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        method = source.get("method") if isinstance(source.get("method"), str) else "<missing>"
        by_source[method] = by_source.get(method, 0) + 1
    data: dict[str, Any] = {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": len(items),
        "audit_provenance": {
            "claim_boundary": "This report separates external audit findings from tool/suite findings and records claim evidence.",
            "automated_tool_found_all": False,
        },
        "claim_summary": {"by_source": by_source, "total_count": len(items)},
        "verification_commands": [
            {"command": "python -m pytest -q", "status": "passed", "exit_code": 0, "artifact": "pytest.log"},
            {"command": "pyright", "status": "skipped", "exit_code": 0, "artifact": "typecheck.json", "skip_reason": "pyright not installed in this environment"},
        ],
        "fixes": items,
    }
    data.update(overrides)
    return data


def _categories(report: Report) -> set[str]:
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def _has_expected(report: Report, prefixes: tuple[str, ...]) -> bool:
    cats = _categories(report)
    return any(any(cat.startswith(prefix) for cat in cats) for prefix in prefixes)


def _suite_issue(case: ClaimSummaryVerificationCase, observed: Iterable[str]) -> Issue:
    return Issue(
        file=f"<claim-summary-verification:{case.case_id}>",
        category="CSVSUITE001: Claim summary verification regression failure",
        severity=Severity.HIGH,
        detector="claim_summary_verification_suite",
        description=f"Fixture was not detected: {case.title}. Observed: {', '.join(sorted(observed)) or '<none>'}.",
        recommendation="Repair claim-summary/verification-command validation and keep this fixture enabled.",
    )


def claim_summary_verification_cases() -> list[ClaimSummaryVerificationCase]:
    return [
        ClaimSummaryVerificationCase("by_source_bool", "claim_summary.by_source rejects bool counts", "claim_summary", ("EVID025",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": True}, "total_count": 1})),
        ClaimSummaryVerificationCase("by_source_float", "claim_summary.by_source rejects non-integer counts", "claim_summary", ("EVID025",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": 1.5}, "total_count": 1})),
        ClaimSummaryVerificationCase("by_source_negative", "claim_summary.by_source rejects negative counts", "claim_summary", ("EVID026",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": -1}, "total_count": 1})),
        ClaimSummaryVerificationCase("by_source_unknown_method", "claim_summary.by_source rejects unsupported source methods", "claim_summary", ("EVID024",), lambda: _doc([_base_item()], claim_summary={"by_source": {"mystery_method": 1}, "total_count": 1})),
        ClaimSummaryVerificationCase("total_count_missing", "claim_summary.total_count is mandatory", "claim_summary", ("EVID027",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": 1}})),
        ClaimSummaryVerificationCase("total_count_bool", "claim_summary.total_count rejects bool", "claim_summary", ("EVID027",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": 1}, "total_count": True})),
        ClaimSummaryVerificationCase("total_count_mismatch", "claim_summary.total_count must match item count", "claim_summary", ("EVID028",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": 1}, "total_count": 2})),
        ClaimSummaryVerificationCase("duplicate_command", "verification_commands rejects duplicate commands", "verification", ("EVID029",), lambda: _doc([_base_item()], verification_commands=[{"command":"pytest","status":"passed","exit_code":0,"artifact":"a.log"},{"command":"pytest","status":"passed","exit_code":0,"artifact":"b.log"}])) ,
        ClaimSummaryVerificationCase("skipped_no_reason", "skipped verification command requires skip_reason", "verification", ("EVID031",), lambda: _doc([_base_item()], verification_commands=[{"command":"pyright","status":"skipped","exit_code":0,"artifact":"typecheck.json"}])) ,
        ClaimSummaryVerificationCase("skipped_nonzero", "skipped verification command must have exit_code zero", "verification", ("EVID030",), lambda: _doc([_base_item()], verification_commands=[{"command":"pyright","status":"skipped","exit_code":1,"artifact":"typecheck.json","skip_reason":"tool unavailable"}])) ,
        ClaimSummaryVerificationCase("suite_tool_without_version", "suite-origin source requires tool_version", "tool_version", ("EVID032", "PROV038"), lambda: _doc([_tool_item(source={"method":"claim_summary_verification_suite","command":"ai-code-filter claim-summary-verification-suite --ci","evidence":["suite.json"]})])),
        ClaimSummaryVerificationCase("suite_tool_bad_version", "suite-origin tool_version must be semver", "tool_version", ("EVID033", "PROV043"), lambda: _doc([_tool_item(source={"method":"claim_summary_verification_suite","command":"ai-code-filter claim-summary-verification-suite --ci","tool_version":"latest","evidence":["suite.json"]})])),
        ClaimSummaryVerificationCase("invalid_review_date", "review_date must be real calendar date", "review_date", ("EVID018",), lambda: _doc([_base_item(source={"method":"external_adversarial_audit","reviewer":"external_acceptance","review_date":"2026-99-99","evidence":["x"]})])),
        ClaimSummaryVerificationCase("non_increasing_versions", "before/after version boundary must increase", "version_boundary", ("EVID036", "PROV042"), lambda: _doc([_base_item(before_version="0.38.0", after_version="0.34.0")])) ,
        ClaimSummaryVerificationCase("valid_summary_and_commands", "valid claim summary and verification evidence are accepted", "false_positive_guards", ("CSV_OK",), lambda: _doc([_base_item(), _tool_item(id="CSV002")])) ,
    ]


def run_claim_summary_verification_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-claim-summary-verification-suite-") as tmp_s:
        tmp = Path(tmp_s)
        for case in claim_summary_verification_cases():
            path = tmp / f"{case.case_id}.json"
            path.write_text(json.dumps(case.payload_factory(), ensure_ascii=False, indent=2), encoding="utf-8")
            observed = validate_claim_evidence_file(path)
            if case.expected_prefixes == ("CSV_OK",):
                if observed.issues:
                    report.extend(observed.issues)
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(_suite_issue(case, _categories(observed)))
    return report


def claim_summary_verification_suite_summary() -> dict[str, Any]:
    cases = claim_summary_verification_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "suite": "claim_summary_verification",
        "case_count": len(cases),
        "threat_classes": sorted(families),
        "by_family": dict(sorted(families.items())),
        "cases": [
            {"case_id": case.case_id, "title": case.title, "family": case.family, "expected_prefixes": list(case.expected_prefixes)}
            for case in cases
        ],
    }
