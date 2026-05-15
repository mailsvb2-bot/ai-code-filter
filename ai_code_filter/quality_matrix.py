from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .baseline_contract import audit_baseline
from .config_contract import audit_config_contract
from .compatibility_audit import audit_compatibility
from .db_consistency import audit_db_consistency
from .golden_fixtures import audit_golden_fixtures
from .grep_audit import audit_grep_patterns
from .deployment_audit import audit_deployment
from .finding_core import FindingCore
from .migration_audit import audit_migrations
from .models import Issue, Report, Severity
from .rule_ownership import audit_rule_ownership
from .rule_quality import audit_rule_quality
from .supply_chain_audit import audit_supply_chain
from .zip_fixture_audit import audit_zip_fixtures
from .ownership_conflicts import audit_ownership_conflicts
from .truthfulness import run_truthfulness_gate, validate_limitations_file
from .policy_as_code import audit_policy_as_code
from .ci_profiles import audit_ci_profiles
from .release_evidence import audit_release_evidence


@dataclass(frozen=True)
class QualityMatrixSummary:
    gates_run: int
    gates_with_blockers: int
    gates_with_skips: int
    total_issues: int

    def to_dict(self) -> dict[str, int]:
        return {
            "gates_run": self.gates_run,
            "gates_with_blockers": self.gates_with_blockers,
            "gates_with_skips": self.gates_with_skips,
            "total_issues": self.total_issues,
        }


def audit_quality_matrix(project: str | Path, *, include_optional: bool = False) -> tuple[Report, QualityMatrixSummary]:
    """Run a deterministic quality-matrix meta gate.

    This gate is intentionally orchestration-only: it does not replace the
    individual audit commands. It proves that the project can be evaluated
    across multiple dimensions and preserves every finding through FindingCore.
    """
    root = Path(project).resolve()
    aggregate = Report()
    gates: list[tuple[str, Callable[[], Report]]] = [
        ("truthfulness", lambda: _truthfulness(root)),
        ("config_contract", lambda: audit_config_contract(root)),
        ("db_consistency", lambda: audit_db_consistency(root)),
        ("rule_ownership", lambda: audit_rule_ownership(root, root / "docs" / "RULE_OWNERSHIP.json")),
        ("rule_quality", lambda: audit_rule_quality(root, root / "docs" / "RULE_OWNERSHIP.json")[0]),
        ("deployment", lambda: audit_deployment(root)),
        ("migration", lambda: audit_migrations(root)),
        ("supply_chain", lambda: audit_supply_chain(root)),
        ("zip_fixtures", lambda: audit_zip_fixtures(root)[0]),
        ("compatibility", lambda: audit_compatibility(root)[0]),
        ("ownership_conflicts", lambda: audit_ownership_conflicts(root)[0]),
        ("grep_audit", lambda: audit_grep_patterns(root)[0]),
        ("policy_as_code", lambda: audit_policy_as_code(root)[0]),
        ("ci_profiles", lambda: audit_ci_profiles(root)[0]),
        ("release_evidence", lambda: audit_release_evidence(root)[0]),
    ]
    golden_root = root / "tests" / "golden"
    if golden_root.exists() and (golden_root / "fixtures.json").exists():
        gates.append(("golden_fixtures", lambda: audit_golden_fixtures(golden_root)[0]))
    if include_optional:
        baseline = root / "baseline.json"
        if baseline.exists():
            gates.append(("baseline", lambda: audit_baseline(baseline, project_root=root)))
        else:
            aggregate.record_skip("<baseline>", "baseline.json not present; optional baseline gate skipped")
    gates_run = 0
    blockers = 0
    skips = 0
    for name, runner in gates:
        gates_run += 1
        try:
            report = runner()
        except Exception as exc:  # pragma: no cover - defensive against gate regressions
            aggregate.add(Issue(file=str(root), category="QM001: quality gate crashed", severity=Severity.HIGH, detector="quality_matrix", description=f"Quality gate {name!r} raised {type(exc).__name__}: {exc}.", recommendation="Fix the gate or exclude it explicitly; crashed gates cannot be treated as green.", confidence="high"))
            blockers += 1
            continue
        if report.has_blocking_issues():
            blockers += 1
        if report.skipped_files:
            skips += 1
        for issue in report.issues:
            aggregate.add(Issue(
                file=issue.file,
                category=f"{name}: {issue.category}",
                severity=issue.severity,
                detector=f"quality_matrix.{issue.detector}",
                description=issue.description,
                recommendation=issue.recommendation,
                location=issue.location,
                line_number=issue.line_number,
                confidence=issue.confidence,
                evidence={"gate": name, "original": issue.evidence or {}},
            ))
        for failed in report.failed_files:
            aggregate.record_failure(f"{name}:{failed.get('file')}", RuntimeError(failed.get("error", "gate failed")))
        for skipped in report.skipped_files:
            aggregate.record_skip(f"{name}:{skipped.get('file')}", skipped.get("reason", "skipped"))
    summary = QualityMatrixSummary(gates_run=gates_run, gates_with_blockers=blockers, gates_with_skips=skips, total_issues=len(aggregate.issues))
    return FindingCore().process(aggregate).report, summary


def write_quality_matrix_summary(path: str | Path | None, summary: QualityMatrixSummary, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"quality_matrix": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _truthfulness(root: Path) -> Report:
    report = validate_limitations_file(root)
    report.extend(run_truthfulness_gate(root).issues)
    return report
