from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .finding_core import FindingCore
from .models import Issue, Report, Severity
from .quality_matrix import audit_quality_matrix
from .release_evidence import audit_release_evidence
from .policy_as_code import audit_policy_as_code
from .ci_profiles import audit_ci_profiles


@dataclass(frozen=True)
class ScorecardSummary:
    score: int
    max_score: int
    gates: int
    blockers: int

    def to_dict(self) -> dict[str, int]:
        return {"score": self.score, "max_score": self.max_score, "gates": self.gates, "blockers": self.blockers}


def audit_scorecard(project: str | Path, *, min_score: int = 85) -> tuple[Report, ScorecardSummary]:
    root = Path(project).resolve()
    aggregate = Report()
    gates = [
        ("quality_matrix", audit_quality_matrix(root)[0]),
        ("release_evidence", audit_release_evidence(root)[0]),
        ("policy_as_code", audit_policy_as_code(root)[0]),
        ("ci_profiles", audit_ci_profiles(root)[0]),
    ]
    blockers = 0
    score = 100
    for name, report in gates:
        if report.has_blocking_issues():
            blockers += 1
        for issue in report.issues:
            penalty = 10 if issue.severity in {Severity.CRITICAL, Severity.HIGH} else 3
            score -= penalty
            aggregate.add(Issue(file=issue.file, category=f"{name}: {issue.category}", severity=issue.severity, detector=f"scorecard.{issue.detector}", description=issue.description, recommendation=issue.recommendation, location=issue.location, line_number=issue.line_number, confidence=issue.confidence, evidence={"gate": name, "original": issue.evidence or {}}))
    score = max(0, score)
    if score < min_score:
        aggregate.add(Issue(file=str(root), category="SCORE001: quality score below budget", severity=Severity.HIGH, detector="scorecard", description=f"Quality score {score}/100 is below required budget {min_score}.", recommendation="Fix blocking findings or lower the budget only with explicit policy approval.", confidence="high", evidence={"score": score, "min_score": min_score}))
    return FindingCore().process(aggregate).report, ScorecardSummary(score, 100, len(gates), blockers)


def write_scorecard_summary(path: str | Path | None, summary: ScorecardSummary, report: Report) -> None:
    """Write a JSON summary when path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"scorecard": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")
