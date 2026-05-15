from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Issue, Report, Severity

@dataclass(frozen=True)
class PrecisionRecallSummary:
    expected_findings: int
    matched_findings: int
    observed_findings: int
    false_positive_budget: int
    recall: float
    precision_proxy: float
    def to_dict(self) -> dict[str, Any]:
        return {"expected_findings": self.expected_findings, "matched_findings": self.matched_findings, "observed_findings": self.observed_findings, "false_positive_budget": self.false_positive_budget, "recall": self.recall, "precision_proxy": self.precision_proxy}

def benchmark_precision_recall(expected_json: str | Path, observed_report_json: str | Path, *, min_recall: float = 0.80, min_precision_proxy: float = 0.70, false_positive_budget: int = 0) -> tuple[Report, PrecisionRecallSummary]:
    report = Report()
    expected = json.loads(Path(expected_json).read_text(encoding="utf-8"))
    observed = json.loads(Path(observed_report_json).read_text(encoding="utf-8"))
    expected_cases = expected.get("cases", []) if isinstance(expected, dict) else []
    observed_issues = observed.get("issues", []) if isinstance(observed, dict) else []
    observed_text = json.dumps(observed_issues, ensure_ascii=False).lower()
    total = matched = 0
    for case in expected_cases:
        for needle in case.get("must_find", []):
            total += 1
            if str(needle).lower() in observed_text:
                matched += 1
            else:
                report.add(Issue(file=str(case.get("path", expected_json)), category="BENCH001: recall miss", severity=Severity.HIGH, detector="precision_recall", description=f"Expected signal was not found: {needle}", recommendation="Strengthen the detector, normalization mapping, or expected corpus labels.", confidence="high", evidence={"case": case}))
    recall = (matched / total) if total else 1.0
    false_positives = max(0, len(observed_issues) - matched)
    precision_proxy = (matched / (matched + false_positives)) if (matched + false_positives) else 1.0
    if recall < min_recall:
        report.add(Issue(file=str(expected_json), category="BENCH002: recall below budget", severity=Severity.HIGH, detector="precision_recall", description=f"Recall {recall:.3f} is below minimum {min_recall:.3f}.", recommendation="Improve detection coverage before claiming the corpus is protected.", confidence="high"))
    if precision_proxy < min_precision_proxy:
        report.add(Issue(file=str(observed_report_json), category="BENCH003: precision proxy below budget", severity=Severity.MEDIUM, detector="precision_recall", description=f"Precision proxy {precision_proxy:.3f} is below minimum {min_precision_proxy:.3f}.", recommendation="Reduce false positives or split noisy rules behind profiles.", confidence="medium"))
    if false_positives > false_positive_budget:
        report.add(Issue(file=str(observed_report_json), category="BENCH004: false positive budget exceeded", severity=Severity.MEDIUM, detector="precision_recall", description=f"Observed {false_positives} proxy false positives; budget is {false_positive_budget}.", recommendation="Triage unmatched findings and add accepted labels or suppressions with owners.", confidence="medium"))
    return report, PrecisionRecallSummary(total, matched, len(observed_issues), false_positive_budget, round(recall, 4), round(precision_proxy, 4))

def write_precision_recall_summary(path: str | Path | None, summary: PrecisionRecallSummary, report: Report) -> None:
    if path:
        Path(path).write_text(json.dumps({"precision_recall": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")
