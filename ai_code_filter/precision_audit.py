from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import DEFAULT_EXTENSIONS, DEFAULT_MODEL, RuntimeConfig
from .finding_core import FindingCore
from .models import Issue, Report, Severity
from .pipeline import AnalysisPipeline


@dataclass(frozen=True)
class PrecisionAuditSummary:
    clean_cases: int
    clean_issues: int
    expected_cases: int
    expected_matches: int

    def to_dict(self) -> dict[str, int]:
        return {
            "clean_cases": self.clean_cases,
            "clean_issues": self.clean_issues,
            "expected_cases": self.expected_cases,
            "expected_matches": self.expected_matches,
        }


def audit_precision_corpus(corpus: str | Path, *, max_clean_issues: int = 0) -> tuple[Report, PrecisionAuditSummary]:
    """Audit a golden/precision corpus.

    Corpus layout is intentionally simple and tool-agnostic:
      clean/                         files expected to produce no findings
      expected.json                  optional expectations

    expected.json shape:
      {"cases": [{"path": "bad.py", "must_find": ["python.subprocess", "shell"]}]}

    This is not a mathematical precision/recall proof. It is a regression gate
    that prevents clean fixtures and known bad fixtures from silently drifting.
    """
    root = Path(corpus).resolve()
    report = Report()
    clean_dir = root / "clean"
    clean_cases = 0
    clean_issues = 0
    if clean_dir.exists():
        clean_files = [p for p in clean_dir.rglob("*") if p.is_file() and p.suffix in set(DEFAULT_EXTENSIONS)]
        clean_cases = len(clean_files)
        for path in clean_files:
            sub_report = _run_analyze(path)
            blocking = [issue for issue in sub_report.issues if issue.severity in {Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM, Severity.LOW}]
            clean_issues += len(blocking)
            if len(blocking) > max_clean_issues:
                report.add(Issue(
                    file=_rel(path, root),
                    category="PRECISION001: clean corpus false positive",
                    severity=Severity.HIGH,
                    detector="precision_audit",
                    description=f"Clean corpus file produced {len(blocking)} finding(s).",
                    recommendation="Either fix the rule false-positive, move the fixture out of clean/, or document the expected finding in expected.json.",
                    confidence="high",
                    evidence={"findings": [i.to_dict() for i in blocking[:20]], "max_clean_issues": max_clean_issues},
                ))
    else:
        report.add(Issue(
            file=str(root),
            category="PRECISION010: clean corpus missing",
            severity=Severity.LOW,
            detector="precision_audit",
            description="No clean/ corpus directory was found.",
            recommendation="Add clean fixtures to continuously measure false positives.",
            confidence="medium",
        ))

    expected_cases = 0
    expected_matches = 0
    expected_path = root / "expected.json"
    if expected_path.exists():
        try:
            data = json.loads(expected_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            report.add(Issue(file=_rel(expected_path, root), category="PRECISION020: invalid expected corpus", severity=Severity.HIGH, detector="precision_audit", description=f"expected.json is invalid JSON: {exc}.", recommendation="Fix the expected corpus JSON.", confidence="high"))
            data = {}
        for case in data.get("cases", []) if isinstance(data, dict) else []:
            expected_cases += 1
            rel_path = str(case.get("path", ""))
            must_find = [str(item) for item in case.get("must_find", [])]
            target = root / rel_path
            if not target.exists():
                report.add(Issue(file=rel_path or _rel(expected_path, root), category="PRECISION021: expected case file missing", severity=Severity.HIGH, detector="precision_audit", description="Expected corpus case references a missing file.", recommendation="Fix expected.json or add the fixture file.", confidence="high", evidence={"case": case}))
                continue
            sub_report = _run_analyze(target)
            text = json.dumps([issue.to_dict() for issue in sub_report.issues], ensure_ascii=False).lower()
            missing = [needle for needle in must_find if needle.lower() not in text]
            if missing:
                report.add(Issue(
                    file=rel_path,
                    category="PRECISION030: expected finding not detected",
                    severity=Severity.HIGH,
                    detector="precision_audit",
                    description="A known-bad golden corpus case did not produce the expected finding signal.",
                    recommendation="Strengthen the detector or update the expectation only with review evidence.",
                    confidence="high",
                    evidence={"missing": missing, "observed_categories": [issue.category for issue in sub_report.issues]},
                ))
            else:
                expected_matches += 1
    summary = PrecisionAuditSummary(clean_cases, clean_issues, expected_cases, expected_matches)
    return FindingCore().process(report).report, summary


def write_precision_summary(path: str | Path | None, summary: PrecisionAuditSummary, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"precision_audit": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _run_analyze(path: Path) -> Report:
    cfg = RuntimeConfig(model=DEFAULT_MODEL, extensions=list(DEFAULT_EXTENSIONS), enable_ai_review=False, enable_drift=False, workers=1)
    return AnalysisPipeline(cfg).analyze_paths([str(path)])


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
