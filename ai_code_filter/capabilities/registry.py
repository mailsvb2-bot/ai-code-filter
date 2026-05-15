from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from ..coverage import ANALYZER_CAPABILITIES
from ..models import Issue, Report, Severity
from ..rules import build_default_catalog

_ALLOWED_STATUSES = {"experimental", "active", "deprecated", "replaced"}
_ALLOWED_DOMAINS = {
    "code_static", "data_flow", "release_integrity", "artifact_integrity",
    "provenance", "evidence", "acceptance", "dependency", "architecture",
}


@dataclass(frozen=True)
class Capability:
    capability_id: str
    title: str
    domain: str
    detector: str
    severity: str
    status: str
    introduced: str
    tests: tuple[str, ...]
    description: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["tests"] = list(self.tests)
        return data


def _deterministic_capabilities() -> list[Capability]:
    result: list[Capability] = []
    for rule in build_default_catalog().rules:
        result.append(Capability(
            capability_id=rule.rule_id,
            title=rule.title,
            domain="code_static",
            detector="rule_catalog",
            severity=rule.severity.value,
            status="active",
            introduced="0.3.0",
            tests=("tests/test_rule_catalog.py",),
            description=rule.rationale,
        ))
    return result


def _analyzer_capabilities() -> list[Capability]:
    result: list[Capability] = []
    for item in ANALYZER_CAPABILITIES:
        detector = str(item.get("detector", "unknown"))
        domain = "code_static"
        if "dataflow" in detector or "data_flow" in detector:
            domain = "data_flow"
        if detector in {"array_ambiguity"}:
            domain = "code_static"
        result.append(Capability(
            capability_id=str(item["rule_id"]),
            title=str(item["title"]),
            domain=domain,
            detector=detector,
            severity=str(item["severity"]),
            status="active",
            introduced="0.6.0",
            tests=("tests/",),
            description=str(item.get("category", "")),
        ))
    return result


def _suite_capabilities() -> list[Capability]:
    data = [
        ("SUITE001", "Adversarial release fixtures", "acceptance", "adversarial_suite", "HIGH", "0.20.0", "tests/test_v20_adversarial_suite.py"),
        ("SUITE002", "Blind-spot regression fixtures", "acceptance", "blindspot_suite", "HIGH", "0.23.0", "tests/test_v23_blindspot_suite.py"),
        ("SUITE003", "Path portability acceptance", "release_integrity", "path_portability_suite", "HIGH", "0.25.0", "tests/test_v25_path_portability_suite.py"),
        ("SUITE004", "Structured file hardening", "artifact_integrity", "structured_hardening_suite", "HIGH", "0.27.0", "tests/test_v27_structured_hardening_suite.py"),
        ("SUITE005", "Encoded collision hardening", "artifact_integrity", "encoded_collision_hardening_suite", "HIGH", "0.29.0", "tests/test_v29_encoded_collision_hardening_suite.py"),
        ("SUITE006", "Provenance honesty", "provenance", "provenance_honesty_suite", "HIGH", "0.31.0", "tests/test_v31_provenance_honesty_suite.py"),
        ("SUITE007", "Claim evidence contract", "evidence", "claim_evidence_contract_suite", "HIGH", "0.33.0", "tests/test_v33_claim_evidence_contract.py"),
        ("SUITE008", "Claim summary verification", "evidence", "claim_summary_verification_suite", "HIGH", "0.35.0", "tests/test_v35_claim_summary_verification.py"),
        ("SUITE009", "Evidence artifact safety", "evidence", "evidence_artifact_safety_suite", "HIGH", "0.36.0", "tests/test_v36_evidence_artifact_safety.py"),
        ("SUITE010", "Array ambiguity acceptance", "code_static", "array_ambiguity_suite", "HIGH", "0.38.0", "tests/test_v37_array_ambiguity.py"),
        ("SUITE011", "Unified capability registry", "architecture", "capability_registry", "MEDIUM", "0.38.0", "tests/test_v38_capability_registry.py"),
        ("SUITE012", "Property-style fuzz acceptance", "acceptance", "fuzz_suite", "HIGH", "0.38.0", "tests/test_v38_fuzz_suite.py"),
        ("SUITE013", "Architecture mass audit", "architecture", "mass_audit", "MEDIUM", "0.38.0", "tests/test_v38_mass_and_dependency_audit.py"),
        ("SUITE014", "Dependency consistency audit", "dependency", "dependency_audit", "HIGH", "0.38.0", "tests/test_v38_mass_and_dependency_audit.py"),
    ]
    return [Capability(cid, title, domain, detector, sev, "active", intro, (test,), title) for cid, title, domain, detector, sev, intro, test in data]


def capability_registry() -> list[Capability]:
    return _deterministic_capabilities() + _analyzer_capabilities() + _suite_capabilities()


def capability_registry_summary() -> dict:
    capabilities = [cap.to_dict() for cap in capability_registry()]
    by_domain: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_detector: dict[str, int] = {}
    for cap in capabilities:
        by_domain[cap["domain"]] = by_domain.get(cap["domain"], 0) + 1
        by_status[cap["status"]] = by_status.get(cap["status"], 0) + 1
        by_detector[cap["detector"]] = by_detector.get(cap["detector"], 0) + 1
    return {
        "schema_version": "1.0",
        "capability_count": len(capabilities),
        "by_domain": dict(sorted(by_domain.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_detector": dict(sorted(by_detector.items())),
        "capabilities": capabilities,
    }


def validate_capability_registry(capabilities: Iterable[Capability] | None = None, project_root: str | Path | None = None) -> Report:
    caps = list(capabilities or capability_registry())
    root = Path(project_root or ".")
    report = Report()
    seen: dict[str, Capability] = {}
    for cap in caps:
        if not cap.capability_id or not cap.capability_id.strip():
            report.add(Issue("<capability-registry>", "Capability registry", Severity.HIGH, "capability_registry", "Capability has a blank id.", "Assign a stable capability_id."))
        if cap.capability_id in seen:
            report.add(Issue("<capability-registry>", "Capability registry", Severity.CRITICAL, "capability_registry", f"Duplicate capability id: {cap.capability_id}", "Keep capability ids globally unique."))
        seen[cap.capability_id] = cap
        if cap.status not in _ALLOWED_STATUSES:
            report.add(Issue(cap.capability_id, "Capability registry", Severity.HIGH, "capability_registry", f"Unsupported capability status: {cap.status}", "Use active, experimental, deprecated or replaced."))
        if cap.domain not in _ALLOWED_DOMAINS:
            report.add(Issue(cap.capability_id, "Capability registry", Severity.HIGH, "capability_registry", f"Unsupported capability domain: {cap.domain}", "Use a known capability domain."))
        if not cap.tests:
            report.add(Issue(cap.capability_id, "Capability registry", Severity.HIGH, "capability_registry", "Capability has no regression test reference.", "Add at least one test path or fixture reference."))
        for test in cap.tests:
            if not test or not isinstance(test, str):
                report.add(Issue(cap.capability_id, "Capability registry", Severity.HIGH, "capability_registry", "Capability test reference is empty or non-string.", "Use stable test path strings."))
                continue
            if test.startswith("tests/") and test != "tests/" and project_root is not None and not (root / test).exists():
                report.add(Issue(cap.capability_id, "Capability registry", Severity.MEDIUM, "capability_registry", f"Referenced test path does not exist: {test}", "Update the capability tests field or add the missing test."))
    return report
