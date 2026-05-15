from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Iterable

from .models import Issue, Report, Severity
from .provenance_honesty import validate_provenance_document

_ALLOWED_EVIDENCE_TYPES = {
    "artifact_report",
    "command_output",
    "regression_test",
    "fixture",
    "manual_review",
}
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
_EXTERNAL_METHODS = {"external_adversarial_audit", "human_review"}
_REGRESSION_METHODS = {"regression_fixture"}
_ALL_METHODS = _TOOL_METHODS | _EXTERNAL_METHODS | _REGRESSION_METHODS
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class ClaimEvidenceCase:
    case_id: str
    title: str
    family: str
    expected_prefixes: tuple[str, ...]
    payload_factory: Callable[[], dict[str, Any]]


def _issue(rule: str, severity: Severity, description: str, file: str = "<claim-evidence>") -> Issue:
    return Issue(
        file=file,
        category=f"{rule}: Claim evidence contract",
        severity=severity,
        detector="claim_evidence_contract",
        description=description,
        recommendation=(
            "Attach source-specific evidence, verification commands, claim summary and reproduction/regression proof "
            "so audit reports cannot blur tool findings, external review findings and hardening hypotheses."
        ),
    )


def _is_non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _items(data: dict[str, Any]) -> list[dict[str, Any]]:
    for field in ("fixes", "findings", "items"):
        raw = data.get(field)
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
    return []


def _source_method(item: dict[str, Any]) -> str | None:
    source = item.get("source")
    if not isinstance(source, dict):
        return None
    method = source.get("method")
    return method if isinstance(method, str) else None


def _valid_version(value: Any) -> bool:
    return isinstance(value, str) and bool(_VERSION_RE.match(value.strip()))


def _version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.strip().split(".")
    return int(major), int(minor), int(patch)


def _valid_review_date(value: Any) -> bool:
    if not isinstance(value, str) or not _DATE_RE.match(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _add_base_issues(target: Report, base: Report) -> None:
    target.extend(base.issues)
    for failed in base.failed_files:
        target.record_failure(failed.file, failed.error)
    for skipped in base.skipped_files:
        target.record_skip(skipped.file, skipped.reason)


def validate_claim_evidence_document(data: dict[str, Any], *, file: str = "<claim-evidence>") -> Report:
    """Validate the evidence contract around audit/fix claims.

    This is intentionally stricter than provenance validation. Provenance says
    *where* a claim came from. This contract checks that the claim has enough
    reproducible evidence to be trusted in release notes or fixes reports.
    """
    report = Report()
    if not isinstance(data, dict):
        report.add(_issue("EVID001", Severity.HIGH, "Claim-evidence document is not a JSON object.", file))
        return report

    _add_base_issues(report, validate_provenance_document(data, file=file))
    items = _items(data)

    claim_summary = data.get("claim_summary")
    if not isinstance(claim_summary, dict):
        report.add(_issue("EVID002", Severity.HIGH, "Document lacks claim_summary object with by_source counts.", file))
    else:
        by_source = claim_summary.get("by_source")
        if not isinstance(by_source, dict) or not by_source:
            report.add(_issue("EVID003", Severity.MEDIUM, "claim_summary.by_source is missing or empty.", file))
        else:
            actual: dict[str, int] = {}
            for item in items:
                method = _source_method(item) or "<missing>"
                actual[method] = actual.get(method, 0) + 1
            for method, declared in by_source.items():
                if method not in _ALL_METHODS and method != "<missing>":
                    report.add(_issue("EVID024", Severity.HIGH, f"claim_summary.by_source contains unsupported source method {method!r}.", file))
                if isinstance(declared, bool) or not isinstance(declared, int):
                    report.add(_issue("EVID025", Severity.HIGH, f"claim_summary.by_source[{method!r}] is not an integer count.", file))
                elif declared < 0:
                    report.add(_issue("EVID026", Severity.HIGH, f"claim_summary.by_source[{method!r}] is negative.", file))
            for method, count in actual.items():
                if by_source.get(method) != count:
                    report.add(_issue("EVID004", Severity.HIGH, f"claim_summary.by_source[{method!r}] does not match item count {count}.", file))
            extra = sorted(set(by_source) - set(actual))
            if extra:
                report.add(_issue("EVID005", Severity.MEDIUM, f"claim_summary.by_source contains sources absent from items: {', '.join(extra)}.", file))
        total_count = claim_summary.get("total_count")
        if isinstance(total_count, bool) or not isinstance(total_count, int):
            report.add(_issue("EVID027", Severity.MEDIUM, "claim_summary.total_count must be an integer matching item count.", file))
        elif total_count != len(items):
            report.add(_issue("EVID028", Severity.HIGH, f"claim_summary.total_count={total_count} does not match item count {len(items)}.", file))

    commands = data.get("verification_commands")
    if not isinstance(commands, list) or not commands:
        report.add(_issue("EVID006", Severity.HIGH, "Document lacks non-empty verification_commands list.", file))
    else:
        seen_commands: set[str] = set()
        for idx, command in enumerate(commands, 1):
            if not isinstance(command, dict):
                report.add(_issue("EVID007", Severity.HIGH, f"verification_commands entry #{idx} is not an object.", file))
                continue
            command_text = command.get("command")
            if not _is_non_empty_str(command_text):
                report.add(_issue("EVID008", Severity.MEDIUM, f"verification_commands entry #{idx} lacks command.", file))
            elif command_text in seen_commands:
                report.add(_issue("EVID029", Severity.MEDIUM, f"verification_commands entry #{idx} duplicates a previous command.", file))
            elif isinstance(command_text, str):
                seen_commands.add(command_text)
            if command.get("status") not in {"passed", "failed", "skipped"}:
                report.add(_issue("EVID009", Severity.MEDIUM, f"verification_commands entry #{idx} has unsupported status.", file))
            exit_code = command.get("exit_code")
            if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code < 0:
                report.add(_issue("EVID010", Severity.MEDIUM, f"verification_commands entry #{idx} has invalid exit_code.", file))
            if command.get("status") == "passed" and exit_code != 0:
                report.add(_issue("EVID011", Severity.HIGH, f"verification_commands entry #{idx} says passed but exit_code={exit_code}.", file))
            if command.get("status") == "failed" and exit_code == 0:
                report.add(_issue("EVID012", Severity.HIGH, f"verification_commands entry #{idx} says failed but exit_code=0.", file))
            if command.get("status") == "skipped":
                if exit_code != 0:
                    report.add(_issue("EVID030", Severity.HIGH, f"verification_commands entry #{idx} says skipped but exit_code={exit_code}.", file))
                if not _is_non_empty_str(command.get("skip_reason")):
                    report.add(_issue("EVID031", Severity.MEDIUM, f"verification_commands entry #{idx} says skipped but lacks skip_reason.", file))
            if not _is_non_empty_str(command.get("artifact")):
                report.add(_issue("EVID013", Severity.LOW, f"verification_commands entry #{idx} lacks artifact reference.", file))

    for idx, item in enumerate(items, 1):
        label = str(item.get("id") or item.get("case_id") or idx)
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        method = source.get("method")
        evidence_type = item.get("evidence_type")
        if evidence_type not in _ALLOWED_EVIDENCE_TYPES:
            report.add(_issue("EVID014", Severity.MEDIUM, f"Item {label} lacks supported evidence_type.", file))
        if method in _TOOL_METHODS and evidence_type not in {"artifact_report", "command_output"}:
            report.add(_issue("EVID015", Severity.HIGH, f"Item {label} is tool-origin but evidence_type={evidence_type!r} is not command/artifact evidence.", file))
        if method in _TOOL_METHODS:
            tool_version = source.get("tool_version")
            if not _is_non_empty_str(tool_version):
                report.add(_issue("EVID032", Severity.MEDIUM, f"Item {label} is tool/suite-origin but lacks source.tool_version.", file))
            elif not _valid_version(tool_version):
                report.add(_issue("EVID033", Severity.MEDIUM, f"Item {label} has invalid source.tool_version format.", file))
        if method in _EXTERNAL_METHODS:
            if evidence_type not in {"manual_review", "fixture", "regression_test"}:
                report.add(_issue("EVID016", Severity.HIGH, f"Item {label} is external-origin but evidence_type={evidence_type!r} is not external/regression evidence.", file))
            if not _is_non_empty_str(source.get("reviewer")):
                report.add(_issue("EVID017", Severity.MEDIUM, f"Item {label} lacks reviewer identity.", file))
            if not _valid_review_date(source.get("review_date")):
                report.add(_issue("EVID018", Severity.MEDIUM, f"Item {label} lacks a real YYYY-MM-DD review_date.", file))
        if method in _REGRESSION_METHODS:
            if evidence_type not in {"regression_test", "fixture"}:
                report.add(_issue("EVID034", Severity.HIGH, f"Item {label} is regression-fixture origin but evidence_type={evidence_type!r} is not regression/fixture evidence.", file))
            if item.get("regression_test") is not True:
                report.add(_issue("EVID035", Severity.MEDIUM, f"Item {label} uses regression_fixture source without regression_test=true.", file))
        before_version = item.get("before_version")
        after_version = item.get("after_version")
        if _valid_version(before_version) and _valid_version(after_version) and _version_tuple(after_version) <= _version_tuple(before_version):
            report.add(_issue("EVID036", Severity.HIGH, f"Item {label} has non-increasing before_version/after_version boundary.", file))
        if item.get("classification") == "reproduced_defect":
            reproduction = item.get("reproduction")
            if not isinstance(reproduction, dict):
                report.add(_issue("EVID019", Severity.HIGH, f"Reproduced defect {label} lacks reproduction object.", file))
            else:
                for key in ("command", "observed_before", "verified_after"):
                    if not _is_non_empty_str(reproduction.get(key)):
                        report.add(_issue("EVID020", Severity.MEDIUM, f"Reproduced defect {label} reproduction.{key} is missing.", file))
        if item.get("regression_test") is True and not _is_non_empty_str(item.get("test_path")):
            report.add(_issue("EVID021", Severity.MEDIUM, f"Item {label} claims regression_test=true but lacks test_path.", file))
        if item.get("classification") in {"blind_spot", "hardening_gap"} and not _is_non_empty_str(item.get("threat_model_gap")):
            report.add(_issue("EVID022", Severity.MEDIUM, f"Item {label} lacks threat_model_gap explaining the missed class.", file))
    return report


def validate_claim_evidence_file(path: Path) -> Report:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        report = Report()
        report.add(_issue("EVID023", Severity.HIGH, f"Could not parse claim-evidence JSON: {type(exc).__name__}: {exc}", str(path)))
        return report
    return validate_claim_evidence_document(data, file=str(path))


def _base_item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
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
    item.update(overrides)
    return item


def _doc(items: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    by_source: dict[str, int] = {}
    for item in items:
        method = _source_method(item) or "<missing>"
        by_source[method] = by_source.get(method, 0) + 1
    data: dict[str, Any] = {
        "artifact_kind": "fixes",
        "schema_version": "1.0",
        "fixed_count": len(items),
        "audit_provenance": {
            "claim_boundary": "Items separate tool, external and regression fixture origins.",
            "automated_tool_found_all": False,
        },
        "claim_summary": {"by_source": by_source, "total_count": len(items)},
        "verification_commands": [
            {"command": "python -m pytest -q", "status": "passed", "exit_code": 0, "artifact": "pytest.log"}
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


def _suite_issue(case: ClaimEvidenceCase, observed: Iterable[str]) -> Issue:
    return Issue(
        file=f"<claim-evidence:{case.case_id}>",
        category="EVIDSUITE001: Claim evidence regression failure",
        severity=Severity.HIGH,
        detector="claim_evidence_contract_suite",
        description=f"Fixture was not detected: {case.title}. Observed: {', '.join(sorted(observed)) or '<none>'}.",
        recommendation="Repair claim-evidence contract validation and keep this fixture enabled.",
    )


def claim_evidence_contract_cases() -> list[ClaimEvidenceCase]:
    return [
        ClaimEvidenceCase("missing_claim_summary", "claim_summary is required", "document_summary", ("EVID002",), lambda: {k: v for k, v in _doc([_base_item()]).items() if k != "claim_summary"}),
        ClaimEvidenceCase("bad_by_source_count", "by_source must match items", "document_summary", ("EVID004",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": 99}})),
        ClaimEvidenceCase("missing_commands", "verification_commands required", "verification", ("EVID006",), lambda: _doc([_base_item()], verification_commands=[])),
        ClaimEvidenceCase("bad_command_status", "command status/exit_code must be coherent", "verification", ("EVID011",), lambda: _doc([_base_item()], verification_commands=[{"command": "pytest", "status": "passed", "exit_code": 1, "artifact": "pytest.log"}])),
        ClaimEvidenceCase("missing_evidence_type", "evidence_type required", "item_evidence", ("EVID014",), lambda: _doc([_base_item(evidence_type=None)])),
        ClaimEvidenceCase("tool_with_manual_evidence", "tool-origin claims need command/artifact evidence", "item_evidence", ("EVID015",), lambda: _doc([_base_item(classification="reproduced_defect", evidence_type="manual_review", source={"method": "tool_self_scan", "command": "ai-code-filter analyze .", "tool_version": "0.38.0", "evidence": ["self.json"]})])),
        ClaimEvidenceCase("external_without_review_date", "external claims require review_date", "external_identity", ("EVID018",), lambda: _doc([_base_item(source={"method": "external_adversarial_audit", "reviewer": "external_acceptance", "evidence": ["x"]})])),
        ClaimEvidenceCase("reproduced_without_reproduction", "reproduced defects require reproduction object", "reproduction", ("EVID019",), lambda: _doc([_base_item(classification="reproduced_defect", evidence_type="artifact_report", source={"method": "release_audit", "command": "ai-code-filter release-audit dist.zip", "tool_version": "0.38.0", "evidence": ["release.json"]})])),
        ClaimEvidenceCase("regression_without_test_path", "regression_test requires test_path", "regression", ("EVID021",), lambda: _doc([_base_item(test_path="")])),
        ClaimEvidenceCase("blindspot_without_threat_gap", "blind spots require threat_model_gap", "threat_model", ("EVID022",), lambda: _doc([_base_item(threat_model_gap="")])),
        ClaimEvidenceCase("bool_by_source_count", "by_source counts must reject bool", "document_summary", ("EVID025",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": True}, "total_count": 1})),
        ClaimEvidenceCase("negative_by_source_count", "by_source counts must reject negative integers", "document_summary", ("EVID026",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": -1}, "total_count": 1})),
        ClaimEvidenceCase("unsupported_by_source_method", "by_source keys must be supported methods", "document_summary", ("EVID024",), lambda: _doc([_base_item()], claim_summary={"by_source": {"mystery_method": 1}, "total_count": 1})),
        ClaimEvidenceCase("missing_total_count", "claim_summary total_count is required", "document_summary", ("EVID027",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": 1}})),
        ClaimEvidenceCase("wrong_total_count", "claim_summary total_count must match items", "document_summary", ("EVID028",), lambda: _doc([_base_item()], claim_summary={"by_source": {"external_adversarial_audit": 1}, "total_count": 2})),
        ClaimEvidenceCase("duplicate_verification_command", "duplicate verification commands are suspicious", "verification", ("EVID029",), lambda: _doc([_base_item()], verification_commands=[{"command": "pytest", "status": "passed", "exit_code": 0, "artifact": "pytest.log"}, {"command": "pytest", "status": "passed", "exit_code": 0, "artifact": "pytest2.log"}])),
        ClaimEvidenceCase("skipped_command_without_reason", "skipped verification commands require reason", "verification", ("EVID031",), lambda: _doc([_base_item()], verification_commands=[{"command": "pyright", "status": "skipped", "exit_code": 0, "artifact": "typecheck.json"}])),
        ClaimEvidenceCase("skipped_command_nonzero", "skipped verification commands must exit cleanly", "verification", ("EVID030",), lambda: _doc([_base_item()], verification_commands=[{"command": "pyright", "status": "skipped", "exit_code": 1, "artifact": "typecheck.json", "skip_reason": "tool missing"}])),
        ClaimEvidenceCase("tool_suite_without_version", "all tool/suite origin claims require tool_version", "item_evidence", ("EVID032",), lambda: _doc([_base_item(classification="reproduced_defect", evidence_type="artifact_report", source={"method": "adversarial_suite", "command": "ai-code-filter adversarial-suite", "evidence": ["adversarial.json"]}, reproduction={"command":"x","observed_before":"bad","verified_after":"good"})])),
        ClaimEvidenceCase("tool_suite_bad_version", "tool_version must be semver", "item_evidence", ("EVID033",), lambda: _doc([_base_item(classification="reproduced_defect", evidence_type="artifact_report", source={"method": "adversarial_suite", "command": "ai-code-filter adversarial-suite", "tool_version": "latest", "evidence": ["adversarial.json"]}, reproduction={"command":"x","observed_before":"bad","verified_after":"good"})])),
        ClaimEvidenceCase("invalid_calendar_review_date", "review_date must be a real calendar date", "external_identity", ("EVID018",), lambda: _doc([_base_item(source={"method": "external_adversarial_audit", "reviewer": "external_acceptance", "review_date": "2026-99-99", "evidence": ["x"]})])),
        ClaimEvidenceCase("regression_fixture_wrong_evidence_type", "regression fixture source requires regression/fixture evidence", "regression", ("EVID034",), lambda: _doc([_base_item(evidence_type="manual_review", source={"method":"regression_fixture", "evidence":["tests/x.py"]})])),
        ClaimEvidenceCase("regression_fixture_without_flag", "regression fixture source requires regression_test flag", "regression", ("EVID035",), lambda: _doc([_base_item(regression_test=False, evidence_type="regression_test", source={"method":"regression_fixture", "evidence":["tests/x.py"]})])),
        ClaimEvidenceCase("non_increasing_versions", "before/after versions must increase", "version_boundary", ("EVID036",), lambda: _doc([_base_item(before_version="0.38.0", after_version="0.32.0")])),
        ClaimEvidenceCase("valid_external_evidence", "valid external evidence contract is accepted", "false_positive_guards", ("EVID_OK",), lambda: _doc([_base_item()])),
    ]


def run_claim_evidence_contract_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-claim-evidence-suite-") as tmp_s:
        tmp = Path(tmp_s)
        for case in claim_evidence_contract_cases():
            path = tmp / f"{case.case_id}.json"
            path.write_text(json.dumps(case.payload_factory(), ensure_ascii=False, indent=2), encoding="utf-8")
            observed = validate_claim_evidence_file(path)
            if case.expected_prefixes == ("EVID_OK",):
                if observed.issues:
                    report.extend(observed.issues)
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(_suite_issue(case, _categories(observed)))
    return report


def claim_evidence_contract_suite_summary() -> dict[str, Any]:
    cases = claim_evidence_contract_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "suite": "claim_evidence_contract",
        "case_count": len(cases),
        "threat_classes": sorted(families),
        "by_family": dict(sorted(families.items())),
        "cases": [
            {"case_id": case.case_id, "title": case.title, "family": case.family, "expected_prefixes": list(case.expected_prefixes)}
            for case in cases
        ],
    }
