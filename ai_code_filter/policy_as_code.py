from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class PolicyAuditSummary:
    policy_path: str
    required_gates: int
    required_artifacts: int
    checked_thresholds: int

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_path": self.policy_path,
            "required_gates": self.required_gates,
            "required_artifacts": self.required_artifacts,
            "checked_thresholds": self.checked_thresholds,
        }


def audit_policy_as_code(project: str | Path, *, policy_path: str | Path | None = None) -> tuple[Report, PolicyAuditSummary]:
    root = Path(project).resolve()
    policy_file = Path(policy_path).resolve() if policy_path else root / "docs" / "QUALITY_POLICY.json"
    report = Report()
    required_gates = 0
    required_artifacts = 0
    checked_thresholds = 0
    if not policy_file.exists():
        report.add(Issue(
            file=str(policy_file),
            category="POL001: missing quality policy",
            severity=Severity.HIGH,
            detector="policy_as_code",
            description="A machine-readable quality policy was not found.",
            recommendation="Create docs/QUALITY_POLICY.json with required gates, artifacts and quality budgets.",
            confidence="high",
        ))
        return FindingCore().process(report).report, PolicyAuditSummary(str(policy_file), 0, 0, 0)
    try:
        policy = json.loads(policy_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.add(Issue(file=str(policy_file), category="POL002: invalid quality policy JSON", severity=Severity.HIGH, detector="policy_as_code", description=f"QUALITY_POLICY.json is not valid JSON: {exc}.", recommendation="Fix the policy JSON before trusting the CI gate.", confidence="high"))
        return FindingCore().process(report).report, PolicyAuditSummary(str(policy_file), 0, 0, 0)
    compat_commands = _load_required_commands(root)
    for gate in _as_list(policy.get("required_gates")):
        required_gates += 1
        if gate not in compat_commands:
            report.add(Issue(
                file=str(policy_file),
                category="POL010: required gate not protected by compatibility registry",
                severity=Severity.HIGH,
                detector="policy_as_code",
                description=f"Quality policy requires gate {gate!r}, but compatibility registry does not protect it.",
                recommendation="Add the command to docs/COMPATIBILITY_REGRESSIONS.json or remove it from required_gates with a documented reason.",
                confidence="high",
                evidence={"gate": gate},
            ))
    for artifact in _as_list(policy.get("required_artifacts")):
        required_artifacts += 1
        candidate = (root / str(artifact)).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            report.add(Issue(file=str(policy_file), category="POL011: artifact escapes project root", severity=Severity.HIGH, detector="policy_as_code", description=f"Required artifact {artifact!r} resolves outside the project root.", recommendation="Keep required artifacts inside the repository.", confidence="high", evidence={"artifact": artifact}))
            continue
        if not candidate.exists():
            report.add(Issue(file=str(policy_file), category="POL012: required policy artifact missing", severity=Severity.MEDIUM, detector="policy_as_code", description=f"Required policy artifact {artifact!r} is missing.", recommendation="Create the artifact or remove it from the quality policy with a documented reason.", confidence="high", evidence={"artifact": artifact}))
    budgets = policy.get("budgets", {})
    if isinstance(budgets, dict):
        for key, value in budgets.items():
            checked_thresholds += 1
            if not isinstance(value, (int, float)) or value < 0:
                report.add(Issue(file=str(policy_file), category="POL020: invalid quality budget", severity=Severity.MEDIUM, detector="policy_as_code", description=f"Quality budget {key!r} must be a non-negative number.", recommendation="Use explicit numeric budgets so CI behavior is deterministic.", confidence="high", evidence={"budget": key, "value": value}))
    else:
        report.add(Issue(file=str(policy_file), category="POL021: invalid budgets object", severity=Severity.MEDIUM, detector="policy_as_code", description="Policy budgets must be an object mapping names to numeric thresholds.", recommendation="Replace budgets with a JSON object.", confidence="high"))
    return FindingCore().process(report).report, PolicyAuditSummary(str(policy_file), required_gates, required_artifacts, checked_thresholds)


def write_policy_summary(path: str | Path | None, summary: PolicyAuditSummary, report: Report) -> None:
    """Write a JSON summary when path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"policy": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_required_commands(root: Path) -> set[str]:
    compat = root / "docs" / "COMPATIBILITY_REGRESSIONS.json"
    if not compat.exists():
        return set()
    try:
        data = json.loads(compat.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return {str(x) for x in data.get("required_commands", []) if isinstance(x, str)}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
