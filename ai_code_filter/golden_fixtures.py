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
class GoldenFixtureSummary:
    cases: int
    matched: int
    missing: int
    forbidden_hits: int

    def to_dict(self) -> dict[str, int]:
        return {"cases": self.cases, "matched": self.matched, "missing": self.missing, "forbidden_hits": self.forbidden_hits}


def audit_golden_fixtures(corpus: str | Path) -> tuple[Report, GoldenFixtureSummary]:
    root = Path(corpus).resolve()
    report = Report()
    spec_path = root / "fixtures.json"
    if not spec_path.exists():
        report.add(Issue(file=str(spec_path), category="GOLDEN001: fixtures spec missing", severity=Severity.HIGH, detector="golden_fixtures", description="Golden fixture corpus must contain fixtures.json.", recommendation="Add real-world/framework-specific fixture expectations with paths, profiles and expected categories.", confidence="high"))
        return report, GoldenFixtureSummary(0, 0, 0, 0)
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.add(Issue(file=str(spec_path), category="GOLDEN002: invalid fixtures spec", severity=Severity.HIGH, detector="golden_fixtures", description=f"fixtures.json is invalid: {exc}", recommendation="Fix JSON syntax.", confidence="high"))
        return report, GoldenFixtureSummary(0, 0, 0, 0)
    cases = spec.get("cases", []) if isinstance(spec, dict) else []
    matched = missing = forbidden_hits = 0
    for case in cases:
        if not isinstance(case, dict):
            continue
        path = root / str(case.get("path", ""))
        name = str(case.get("name") or path.name)
        expected = [str(x) for x in case.get("expected_categories", [])]
        forbidden = [str(x) for x in case.get("forbid_categories", [])]
        profiles = tuple(str(x) for x in case.get("profiles", []) or ("generic",))
        if not path.exists():
            missing += len(expected) or 1
            report.add(Issue(file=str(path), category="GOLDEN010: fixture file missing", severity=Severity.HIGH, detector="golden_fixtures", description=f"Fixture {name!r} references a missing file.", recommendation="Add the fixture or fix fixtures.json.", confidence="high"))
            continue
        cfg = RuntimeConfig(model=DEFAULT_MODEL, extensions=list(DEFAULT_EXTENSIONS), enable_ai_review=False, enable_drift=False, workers=1, profiles=profiles)
        sub = AnalysisPipeline(cfg).analyze_paths([str(path)])
        cats = {issue.category for issue in sub.issues}
        for cat in expected:
            if cat in cats:
                matched += 1
            else:
                missing += 1
                report.add(Issue(file=_rel(path, root), category="GOLDEN020: expected fixture finding missing", severity=Severity.HIGH, detector="golden_fixtures", description=f"Fixture {name!r} did not produce expected category {cat!r}.", recommendation="Fix the detector or update the fixture only with review evidence.", confidence="high", evidence={"profiles": profiles, "observed_categories": sorted(cats)}))
        for cat in forbidden:
            if cat in cats:
                forbidden_hits += 1
                report.add(Issue(file=_rel(path, root), category="GOLDEN030: forbidden fixture finding present", severity=Severity.HIGH, detector="golden_fixtures", description=f"Fixture {name!r} produced forbidden category {cat!r}.", recommendation="Fix the false positive or update the fixture only with review evidence.", confidence="high", evidence={"profiles": profiles, "observed_categories": sorted(cats)}))
    processed = FindingCore().process(report).report
    return processed, GoldenFixtureSummary(len(cases), matched, missing, forbidden_hits)


def write_golden_fixture_summary(path: str | Path | None, summary: GoldenFixtureSummary, report: Report) -> None:
    """Write a summary JSON file; returns None when no path is supplied."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"golden_fixtures": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
