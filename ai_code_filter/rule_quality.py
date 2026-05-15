from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity
from .rule_ownership import DEFAULT_REGISTRY


@dataclass(frozen=True)
class RuleQualitySummary:
    rules: int
    rules_with_tests: int
    rules_with_known_gaps: int
    weak_entries: int

    def to_dict(self) -> dict[str, int]:
        return {
            "rules": self.rules,
            "rules_with_tests": self.rules_with_tests,
            "rules_with_known_gaps": self.rules_with_known_gaps,
            "weak_entries": self.weak_entries,
        }


def audit_rule_quality(project: str | Path, registry_path: str | Path | None = None) -> tuple[Report, RuleQualitySummary]:
    """Audit the quality passport of the rule registry.

    This is stricter than ownership: it asks every rule to document test evidence,
    coverage modes, known gaps and precision/recall estimates. The estimates are
    still human-maintained, but this gate prevents silent rule-quality claims.
    """
    root = Path(project).resolve()
    path = Path(registry_path) if registry_path else root / DEFAULT_REGISTRY
    report = Report()
    if not path.exists():
        report.add(Issue(file=str(path), category="rule_quality.missing_registry", severity=Severity.HIGH, detector="rule_quality", description="Rule quality registry source is missing.", recommendation="Create docs/RULE_OWNERSHIP.json with quality fields per rule.", confidence="high"))
        return FindingCore().process(report).report, RuleQualitySummary(0, 0, 0, 1)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.add(Issue(file=str(path), category="rule_quality.invalid_json", severity=Severity.HIGH, detector="rule_quality", description=f"Rule registry JSON is invalid: {exc}.", recommendation="Fix JSON syntax before trusting rule quality metadata.", confidence="high"))
        return FindingCore().process(report).report, RuleQualitySummary(0, 0, 0, 1)
    if not isinstance(data, dict):
        report.add(Issue(file=str(path), category="rule_quality.invalid_shape", severity=Severity.HIGH, detector="rule_quality", description="Rule registry must be an object keyed by rule id.", recommendation="Use {'RULE': {...}} shape.", confidence="high"))
        return FindingCore().process(report).report, RuleQualitySummary(0, 0, 0, 1)

    tests_text = _read_tests_text(root)
    weak = 0
    with_tests = 0
    with_gaps = 0
    allowed_precision = {"low", "medium", "high"}
    allowed_status = {"experimental", "stable", "deprecated"}
    for rule_id, entry in sorted(data.items()):
        if not isinstance(entry, dict):
            weak += 1
            report.add(Issue(file=str(path), category="rule_quality.invalid_entry", severity=Severity.HIGH, detector="rule_quality", description=f"{rule_id} entry is not an object.", recommendation="Use an object with owner/status/precision/coverage/known_gaps/tests.", confidence="high"))
            continue
        coverage = entry.get("coverage")
        gaps = entry.get("known_gaps")
        tests = entry.get("tests", [])
        precision = str(entry.get("precision", "")).lower()
        status = str(entry.get("status", "")).lower()
        if precision not in allowed_precision:
            weak += 1
            report.add(Issue(file=str(path), category="rule_quality.invalid_precision", severity=Severity.MEDIUM, detector="rule_quality", description=f"{rule_id} has invalid precision value {entry.get('precision')!r}.", recommendation="Use low/medium/high and keep estimates conservative.", confidence="high", evidence={"rule_id": rule_id}))
        if status not in allowed_status:
            weak += 1
            report.add(Issue(file=str(path), category="rule_quality.invalid_status", severity=Severity.MEDIUM, detector="rule_quality", description=f"{rule_id} has invalid status value {entry.get('status')!r}.", recommendation="Use experimental/stable/deprecated.", confidence="high", evidence={"rule_id": rule_id}))
        if not isinstance(coverage, list) or not coverage:
            weak += 1
            report.add(Issue(file=str(path), category="rule_quality.missing_coverage_modes", severity=Severity.MEDIUM, detector="rule_quality", description=f"{rule_id} has no coverage modes.", recommendation="Document supported modes such as direct_call, alias_call, wrapper_depth=1, cross_file_simple.", confidence="high", evidence={"rule_id": rule_id}))
        if isinstance(gaps, list) and gaps:
            with_gaps += 1
        else:
            weak += 1
            report.add(Issue(file=str(path), category="rule_quality.missing_known_gaps", severity=Severity.MEDIUM, detector="rule_quality", description=f"{rule_id} does not document known gaps.", recommendation="List at least one known limitation or explicitly document reviewed_none with evidence.", confidence="high", evidence={"rule_id": rule_id}))
        if isinstance(tests, list) and tests:
            with_tests += 1
            missing_refs = [str(t) for t in tests if str(t) not in tests_text]
            if missing_refs:
                weak += 1
                report.add(Issue(file=str(path), category="rule_quality.test_reference_missing", severity=Severity.MEDIUM, detector="rule_quality", description=f"{rule_id} references tests that were not found in tests/.", recommendation="Fix the test references or add regression tests for this rule.", confidence="medium", evidence={"rule_id": rule_id, "missing": missing_refs[:10]}))
        else:
            # Keep this LOW so existing v54 registries remain usable, but visible.
            weak += 1
            report.add(Issue(file=str(path), category="rule_quality.missing_test_evidence", severity=Severity.LOW, detector="rule_quality", description=f"{rule_id} has no test evidence references.", recommendation="Add a tests list with regression test names or fixture ids for the rule.", confidence="medium", evidence={"rule_id": rule_id}))
    summary = RuleQualitySummary(rules=len(data), rules_with_tests=with_tests, rules_with_known_gaps=with_gaps, weak_entries=weak)
    return FindingCore().process(report).report, summary


def write_rule_quality_summary(path: str | Path | None, summary: RuleQualitySummary, report: Report) -> None:
    """Write rule quality summary JSON when a path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"rule_quality": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_tests_text(root: Path) -> str:
    tests_root = root / "tests"
    chunks: list[str] = []
    if tests_root.exists():
        for path in tests_root.rglob("*.py"):
            try:
                chunks.append(path.name)
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return "\n".join(chunks)
