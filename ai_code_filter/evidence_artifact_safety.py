from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

from .claim_evidence_contract import validate_claim_evidence_document, validate_claim_evidence_file
from .models import Issue, Report, Severity

_ALLOWED_SOURCE_METHODS = {
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
_URL_SCHEMES = {"http", "https", "ftp", "file", "s3", "gs"}
_DANGEROUS_COMMAND_TOKENS = (
    "\n", "\r", "&&", "||", ";", "`", "$(", "${", " >", ">>", "<", "|", "\x00"
)
_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_ALLOWED_TEST_EXTS = {".py"}
_ALLOWED_FIX_STATUSES = {"fixed", "verified"}
_PLACEHOLDER_REVIEWERS = {"unknown", "n/a", "na", "none", "tbd", "anonymous"}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class EvidenceArtifactSafetyCase:
    case_id: str
    title: str
    family: str
    expected_prefixes: tuple[str, ...]
    payload_factory: Callable[[], dict[str, Any]]


def _issue(rule: str, severity: Severity, description: str, file: str = "<evidence-artifact-safety>") -> Issue:
    return Issue(
        file=file,
        category=f"{rule}: Evidence artifact safety",
        severity=severity,
        detector="evidence_artifact_safety",
        description=description,
        recommendation=(
            "Keep evidence, artifacts, test paths, reviewer identities, dates, commands and fix statuses "
            "safe, local, reproducible and policy-compatible."
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


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme.lower() in _URL_SCHEMES or value.startswith("//")


def _has_windows_drive(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", value))


def _path_safety_problem(value: Any, *, allow_remote: bool = False) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "reference is not a non-empty string"
    ref = value.strip()
    if ref != value:
        return "reference has leading/trailing whitespace"
    if _CONTROL_RE.search(ref):
        return "reference contains control/NUL characters"
    if _is_url(ref):
        return None if allow_remote else "remote/URL reference is not allowed without explicit policy"
    if ref.startswith("~"):
        return "home-shorthand reference is not allowed"
    if _has_windows_drive(ref):
        return "Windows-drive reference is not allowed"
    if ref.startswith("/") or ref.startswith("\\"):
        return "absolute reference is not allowed"
    if "\\" in ref:
        return "backslash reference is not allowed"
    parts = PurePosixPath(ref).parts
    if any(part in {"", ".", ".."} for part in parts):
        return "dot/traversal path component is not allowed"
    if any(part.strip() != part for part in parts):
        return "path component has leading/trailing whitespace"
    return None


def _valid_semver(value: Any) -> bool:
    return isinstance(value, str) and bool(_SEMVER_RE.match(value.strip()))


def _version_tuple(value: str) -> tuple[int, int, int]:
    a, b, c = value.strip().split(".")
    return int(a), int(b), int(c)


def _real_date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _add_base_issues(target: Report, base: Report) -> None:
    target.extend(base.issues)
    for failed in base.failed_files:
        target.record_failure(failed["file"], RuntimeError(failed["error"]))
    for skipped in base.skipped_files:
        target.record_skip(skipped["file"], skipped["reason"])


def validate_evidence_artifact_safety_document(data: dict[str, Any], *, file: str = "<evidence-artifact-safety>") -> Report:
    report = Report()
    if not isinstance(data, dict):
        report.add(_issue("EAS001", Severity.HIGH, "Evidence safety document is not a JSON object.", file))
        return report

    _add_base_issues(report, validate_claim_evidence_document(data, file=file))
    items = _items(data)

    # Verification command safety.
    commands = data.get("verification_commands")
    if isinstance(commands, list):
        seen_commands: set[str] = set()
        seen_artifacts: dict[str, int] = {}
        for idx, command in enumerate(commands, 1):
            if not isinstance(command, dict):
                continue
            text = command.get("command")
            if isinstance(text, str):
                stripped = text.strip()
                if text != stripped:
                    report.add(_issue("EAS014", Severity.MEDIUM, f"verification_commands entry #{idx} has leading/trailing whitespace in command.", file))
                if stripped in seen_commands:
                    report.add(_issue("EAS015", Severity.MEDIUM, f"verification_commands entry #{idx} duplicates a previous command after normalization.", file))
                seen_commands.add(stripped)
                if any(token in text for token in _DANGEROUS_COMMAND_TOKENS):
                    report.add(_issue("EAS013", Severity.HIGH, f"verification_commands entry #{idx} contains shell-control/newline token.", file))
            artifact = command.get("artifact")
            if isinstance(artifact, str):
                problem = _path_safety_problem(artifact)
                if problem:
                    report.add(_issue("EAS007", Severity.HIGH, f"verification_commands entry #{idx} has unsafe artifact reference: {problem}.", file))
                key = artifact.strip()
                if key in seen_artifacts:
                    report.add(_issue("EAS012", Severity.MEDIUM, f"verification_commands entry #{idx} reuses artifact from entry #{seen_artifacts[key]}.", file))
                seen_artifacts[key] = idx
            elif artifact is not None:
                report.add(_issue("EAS008", Severity.MEDIUM, f"verification_commands entry #{idx} artifact is not a string.", file))

    artifact_kind = data.get("artifact_kind")
    today = date.today()
    for idx, item in enumerate(items, 1):
        label = str(item.get("id") or item.get("case_id") or idx)
        status = item.get("status")
        if artifact_kind == "fixes" and status not in _ALLOWED_FIX_STATUSES:
            report.add(_issue("EAS027", Severity.HIGH, f"Fix item {label} has non-final status {status!r}.", file))
        if item.get("classification") == "policy_gap" and not _is_non_empty_str(item.get("threat_model_gap")):
            report.add(_issue("EAS029", Severity.MEDIUM, f"Policy gap {label} lacks threat_model_gap.", file))

        before = item.get("before_version")
        after = item.get("after_version")
        if before is not None and not _valid_semver(before):
            report.add(_issue("EAS024", Severity.MEDIUM, f"Item {label} has non-canonical before_version.", file))
        if after is not None and not _valid_semver(after):
            report.add(_issue("EAS025", Severity.MEDIUM, f"Item {label} has non-canonical after_version.", file))
        if _valid_semver(before) and _valid_semver(after):
            bv = _version_tuple(before)
            av = _version_tuple(after)
            if av[0] - bv[0] > 10 or av[1] - bv[1] > 100:
                report.add(_issue("EAS026", Severity.MEDIUM, f"Item {label} has unrealistic version jump {before} -> {after}.", file))

        test_path = item.get("test_path")
        if test_path is not None:
            problem = _path_safety_problem(test_path)
            if problem:
                report.add(_issue("EAS020", Severity.HIGH, f"Item {label} has unsafe test_path: {problem}.", file))
            elif PurePosixPath(str(test_path)).suffix not in _ALLOWED_TEST_EXTS:
                report.add(_issue("EAS022", Severity.MEDIUM, f"Item {label} test_path must reference a Python regression test file.", file))

        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        method = source.get("method")
        evidence = source.get("evidence")
        if isinstance(evidence, list):
            seen_evidence: set[str] = set()
            for eidx, entry in enumerate(evidence, 1):
                problem = _path_safety_problem(entry)
                if problem:
                    report.add(_issue("EAS002", Severity.HIGH, f"Item {label} source.evidence entry #{eidx} is unsafe: {problem}.", file))
                if isinstance(entry, str):
                    key = entry.strip()
                    if key in seen_evidence:
                        report.add(_issue("EAS006", Severity.MEDIUM, f"Item {label} duplicates source.evidence entry {key!r}.", file))
                    seen_evidence.add(key)
        reviewer = source.get("reviewer")
        if method in {"external_adversarial_audit", "human_review"}:
            if isinstance(reviewer, str):
                normalized = " ".join(reviewer.split()).strip().lower()
                if reviewer != reviewer.strip() or "  " in reviewer:
                    report.add(_issue("EAS017", Severity.MEDIUM, f"Item {label} reviewer identity is not normalized.", file))
                if normalized in _PLACEHOLDER_REVIEWERS:
                    report.add(_issue("EAS016", Severity.HIGH, f"Item {label} reviewer identity is a placeholder.", file))
            review_date = _real_date(source.get("review_date"))
            if review_date and review_date > today:
                report.add(_issue("EAS018", Severity.HIGH, f"Item {label} review_date is in the future.", file))
        if method not in _ALLOWED_SOURCE_METHODS and isinstance(method, str):
            report.add(_issue("EAS030", Severity.MEDIUM, f"Item {label} has source.method outside evidence-safety allowlist: {method!r}.", file))
    return report


def validate_evidence_artifact_safety_file(path: str | Any) -> Report:
    from pathlib import Path
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        report = Report()
        report.add(_issue("EAS031", Severity.HIGH, f"Could not parse evidence safety JSON: {type(exc).__name__}: {exc}", str(p)))
        return report
    return validate_evidence_artifact_safety_document(data, file=str(p))


def _base_item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": "EAS001",
        "title": "Evidence artifact safety case",
        "classification": "hardening_gap",
        "status": "fixed",
        "before_version": "0.35.0",
        "after_version": "0.38.0",
        "regression_test": True,
        "test_path": "tests/test_v38_evidence_artifact_safety.py",
        "evidence_type": "manual_review",
        "threat_model_gap": "Evidence and verification references need safety and reproducibility checks.",
        "source": {
            "method": "external_adversarial_audit",
            "reviewer": "external_acceptance",
            "review_date": "2026-05-14",
            "evidence": ["tests/test_v38_evidence_artifact_safety.py::test_case"],
        },
    }
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
            "claim_boundary": "This report separates tool, suite and external audit evidence sources.",
            "automated_tool_found_all": False,
        },
        "claim_summary": {"by_source": by_source, "total_count": len(items)},
        "verification_commands": [
            {"command": "python -m pytest -q", "status": "passed", "exit_code": 0, "artifact": "artifacts/pytest.log"},
        ],
        "fixes": items,
    }
    data.update(overrides)
    return data


def _cats(report: Report) -> set[str]:
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def _has_expected(report: Report, prefixes: tuple[str, ...]) -> bool:
    cats = _cats(report)
    return any(any(cat.startswith(prefix) for cat in cats) for prefix in prefixes)


@dataclass(frozen=True)
class _Case:
    case_id: str
    title: str
    family: str
    expected_prefixes: tuple[str, ...]
    payload_factory: Callable[[], dict[str, Any]]


def evidence_artifact_safety_cases() -> list[_Case]:
    def src_evidence(entry: Any) -> dict[str, Any]:
        item = _base_item()
        item["source"] = dict(item["source"], evidence=[entry])
        return _doc([item])
    def cmd_artifact(value: Any) -> dict[str, Any]:
        return _doc([_base_item()], verification_commands=[{"command":"python -m pytest -q","status":"passed","exit_code":0,"artifact":value}])
    return [
        _Case("evidence_traversal", "source.evidence rejects traversal", "evidence_paths", ("EAS002",), lambda: src_evidence("../secret.txt")),
        _Case("evidence_absolute", "source.evidence rejects absolute", "evidence_paths", ("EAS002",), lambda: src_evidence("/etc/passwd")),
        _Case("evidence_windows_drive", "source.evidence rejects Windows drive", "evidence_paths", ("EAS002",), lambda: src_evidence("C:/secret.txt")),
        _Case("evidence_remote_url", "source.evidence rejects remote URL", "evidence_paths", ("EAS002",), lambda: src_evidence("https://example.com/report.json")),
        _Case("evidence_home_shorthand", "source.evidence rejects home shorthand", "evidence_paths", ("EAS002",), lambda: src_evidence("~/secret.json")),
        _Case("evidence_control", "source.evidence rejects control chars", "evidence_paths", ("EAS002",), lambda: src_evidence("reports/bad\x00.json")),
        _Case("evidence_duplicate", "source.evidence rejects duplicate entries", "evidence_paths", ("EAS006",), lambda: _doc([_base_item(source={"method":"external_adversarial_audit","reviewer":"external_acceptance","review_date":"2026-05-14","evidence":["a.json","a.json"]})])),
        _Case("artifact_traversal", "verification artifact rejects traversal", "artifact_paths", ("EAS007",), lambda: cmd_artifact("../pytest.log")),
        _Case("artifact_absolute", "verification artifact rejects absolute", "artifact_paths", ("EAS007",), lambda: cmd_artifact("/tmp/pytest.log")),
        _Case("artifact_windows_drive", "verification artifact rejects Windows drive", "artifact_paths", ("EAS007",), lambda: cmd_artifact("C:/pytest.log")),
        _Case("artifact_url", "verification artifact rejects URL", "artifact_paths", ("EAS007",), lambda: cmd_artifact("https://example.com/pytest.log")),
        _Case("artifact_control", "verification artifact rejects control chars", "artifact_paths", ("EAS007",), lambda: cmd_artifact("bad\x00.log")),
        _Case("artifact_duplicate", "verification artifact duplicate is reported", "artifact_paths", ("EAS012",), lambda: _doc([_base_item()], verification_commands=[{"command":"pytest -q","status":"passed","exit_code":0,"artifact":"pytest.log"},{"command":"python -m pytest -q","status":"passed","exit_code":0,"artifact":"pytest.log"}])),
        _Case("command_newline", "verification command rejects newline injection", "commands", ("EAS013",), lambda: _doc([_base_item()], verification_commands=[{"command":"pytest -q\nrm -rf /","status":"passed","exit_code":0,"artifact":"pytest.log"}])),
        _Case("command_chaining", "verification command rejects shell chaining", "commands", ("EAS013",), lambda: _doc([_base_item()], verification_commands=[{"command":"pytest -q && rm -rf /","status":"passed","exit_code":0,"artifact":"pytest.log"}])),
        _Case("command_duplicate_trim", "verification command duplicate normalizes whitespace", "commands", ("EAS014", "EAS015"), lambda: _doc([_base_item()], verification_commands=[{"command":"pytest -q","status":"passed","exit_code":0,"artifact":"a.log"},{"command":"pytest -q ","status":"passed","exit_code":0,"artifact":"b.log"}])),
        _Case("reviewer_unknown", "reviewer placeholder rejected", "reviewer", ("EAS016",), lambda: _doc([_base_item(source={"method":"human_review","reviewer":"unknown","review_date":"2026-05-14","evidence":["x.json"]})])),
        _Case("reviewer_spaces", "reviewer identity normalized", "reviewer", ("EAS017",), lambda: _doc([_base_item(source={"method":"human_review","reviewer":" external  auditor ","review_date":"2026-05-14","evidence":["x.json"]})])),
        _Case("future_review_date", "future review date rejected", "dates", ("EAS018",), lambda: _doc([_base_item(source={"method":"human_review","reviewer":"external_acceptance","review_date":"2999-01-01","evidence":["x.json"]})])),
        _Case("test_path_traversal", "test_path rejects traversal", "test_paths", ("EAS020",), lambda: _doc([_base_item(test_path="../tests/test.py")])) ,
        _Case("test_path_absolute", "test_path rejects absolute", "test_paths", ("EAS020",), lambda: _doc([_base_item(test_path="/tests/test.py")])) ,
        _Case("test_path_bad_ext", "test_path must be Python test", "test_paths", ("EAS022",), lambda: _doc([_base_item(test_path="tests/test.txt")])) ,
        _Case("test_path_url", "test_path rejects URL", "test_paths", ("EAS020",), lambda: _doc([_base_item(test_path="https://example.com/test.py")])) ,
        _Case("before_leading_zero", "before_version rejects leading zero semver", "versions", ("EAS024",), lambda: _doc([_base_item(before_version="00.38.0")])) ,
        _Case("after_leading_zero", "after_version rejects leading zero semver", "versions", ("EAS025",), lambda: _doc([_base_item(after_version="00.38.0")])) ,
        _Case("unrealistic_jump", "unrealistic version jump rejected", "versions", ("EAS026",), lambda: _doc([_base_item(after_version="999.0.0")])) ,
        _Case("fix_status_detected", "fixes report rejects detected status", "status", ("EAS027",), lambda: _doc([_base_item(status="detected")])) ,
        _Case("fix_status_guarded", "fixes report rejects guarded status", "status", ("EAS027",), lambda: _doc([_base_item(status="guarded")])) ,
        _Case("policy_gap_no_threat", "policy gap requires threat_model_gap", "policy", ("EAS029",), lambda: _doc([_base_item(classification="policy_gap", threat_model_gap="")])) ,
        _Case("valid_evidence_safety", "valid evidence artifact contract accepted", "false_positive_guards", ("EAS_OK",), lambda: _doc([_base_item()])) ,
    ]


def run_evidence_artifact_safety_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-evidence-artifact-safety-") as tmp_s:
        from pathlib import Path
        tmp = Path(tmp_s)
        for case in evidence_artifact_safety_cases():
            path = tmp / f"{case.case_id}.json"
            path.write_text(json.dumps(case.payload_factory(), ensure_ascii=False, indent=2), encoding="utf-8")
            observed = validate_evidence_artifact_safety_file(path)
            if case.expected_prefixes == ("EAS_OK",):
                if observed.issues:
                    report.extend(observed.issues)
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(Issue(
                    file=f"<evidence-artifact-safety:{case.case_id}>",
                    category="EASSUITE001: Evidence artifact safety regression failure",
                    severity=Severity.HIGH,
                    detector="evidence_artifact_safety_suite",
                    description=f"Fixture was not detected: {case.title}. Observed: {', '.join(sorted(_cats(observed))) or '<none>'}.",
                    recommendation="Repair evidence/artifact safety validation and keep this fixture enabled.",
                ))
    return report


def evidence_artifact_safety_suite_summary() -> dict[str, Any]:
    cases = evidence_artifact_safety_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "case_count": len(cases),
        "families": dict(sorted(families.items())),
        "threat_classes": [
            "unsafe_evidence_paths",
            "unsafe_verification_artifacts",
            "verification_command_injection",
            "reviewer_identity_and_date_quality",
            "unsafe_test_paths",
            "non_canonical_version_boundaries",
            "fix_status_policy",
            "policy_gap_evidence",
        ],
        "cases": [
            {"case_id": c.case_id, "family": c.family, "title": c.title, "expected_prefixes": list(c.expected_prefixes)}
            for c in cases
        ],
    }
