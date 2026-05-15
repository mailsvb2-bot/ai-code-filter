from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity

REQUIRED_COMMANDS = {
    "analyze", "call-graph", "pytest-audit", "behavior-audit", "coverage-audit", "mutation-audit",
    "type-audit", "external-audit", "external-normalize", "deployment-audit", "migration-audit", "supply-chain-audit",
    "precision-audit", "golden-fixtures", "zip-fixture-audit", "compatibility-audit", "ownership-conflicts",
    "stress-audit", "quality-matrix", "rule-quality", "grep-audit", "db-consistency", "config-contract",
}

@dataclass(frozen=True)
class CompatibilitySummary:
    required_commands: int
    missing_commands: int
    checked_registry: bool

    def to_dict(self) -> dict[str, Any]:
        return {"required_commands": self.required_commands, "missing_commands": self.missing_commands, "checked_registry": self.checked_registry}


def audit_compatibility(project: str | Path, registry: str | Path | None = None) -> tuple[Report, CompatibilitySummary]:
    root = Path(project).resolve()
    report = Report()
    from .cli import build_parser
    parser = build_parser()
    commands = set(parser._subparsers._group_actions[0].choices)  # argparse public enough for this gate
    missing = sorted(REQUIRED_COMMANDS - commands)
    for cmd in missing:
        report.add(Issue(file="ai_code_filter/cli.py", category="COMPAT001: required CLI command missing", severity=Severity.HIGH, detector="compatibility_audit", description=f"Required compatibility command {cmd!r} is missing.", recommendation="Restore the command or intentionally update the compatibility registry with migration notes.", confidence="high"))
    checked_registry = False
    reg = Path(registry) if registry else root / "docs" / "COMPATIBILITY_REGRESSIONS.json"
    if reg.exists():
        checked_registry = True
        try:
            data = json.loads(reg.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            report.add(Issue(file=str(reg), category="COMPAT010: invalid compatibility registry", severity=Severity.HIGH, detector="compatibility_audit", description=str(exc), recommendation="Fix JSON syntax.", confidence="high"))
            data = {}
        for item in data.get("required_commands", []) if isinstance(data, dict) else []:
            if item not in commands:
                report.add(Issue(file=str(reg), category="COMPAT011: registry command missing", severity=Severity.HIGH, detector="compatibility_audit", description=f"Registry-required command {item!r} is missing.", recommendation="Restore command or update compatibility migration plan.", confidence="high"))
    return FindingCore().process(report).report, CompatibilitySummary(len(REQUIRED_COMMANDS), len(missing), checked_registry)


def write_compatibility_summary(path: str | Path | None, summary: CompatibilitySummary, report: Report) -> None:
    """Write a summary JSON file; returns None when no path is supplied."""
    if not path: return
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"compatibility_audit": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")
