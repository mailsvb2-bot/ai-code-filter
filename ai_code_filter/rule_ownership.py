from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Issue, Report, Severity
from .rules import build_default_catalog

DEFAULT_REGISTRY = Path("docs/RULE_OWNERSHIP.json")


def default_rule_ownership() -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    for rule in build_default_catalog().rules:
        owner = "security" if any(token in rule.category.lower() for token in ("security", "injection", "secret", "unsafe")) else "analysis"
        registry[rule.rule_id] = {
            "owner": owner,
            "status": "stable",
            "precision": "medium",
            "coverage": ["direct_call", "alias_call"],
            "known_gaps": ["dynamic_getattr", "runtime_reflection", "wrapper_depth>1"],
        }
    return registry


def write_default_registry(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(default_rule_ownership(), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def audit_rule_ownership(project: str | Path, registry_path: str | Path | None = None) -> Report:
    root = Path(project)
    path = Path(registry_path) if registry_path else root / DEFAULT_REGISTRY
    report = Report()
    if not path.exists():
        report.add(Issue(
            file=str(path),
            category="rule_ownership.missing_registry",
            severity=Severity.HIGH,
            detector="rule_ownership",
            description="Rule ownership registry is missing.",
            recommendation="Create docs/RULE_OWNERSHIP.json with owner/status/precision/coverage/known_gaps per rule.",
            confidence="high",
        ))
        return report
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.add(Issue(file=str(path), category="rule_ownership.invalid_json", severity=Severity.HIGH, detector="rule_ownership", description=str(exc), recommendation="Fix JSON syntax.", confidence="high"))
        return report
    if not isinstance(data, dict):
        report.add(Issue(file=str(path), category="rule_ownership.invalid_shape", severity=Severity.HIGH, detector="rule_ownership", description="Registry must be an object keyed by rule id.", recommendation="Use {'rule.id': {...}} shape.", confidence="high"))
        return report
    expected = {rule.rule_id for rule in build_default_catalog().rules}
    present = set(data)
    for missing in sorted(expected - present):
        report.add(Issue(file=str(path), category="rule_ownership.missing_rule", severity=Severity.HIGH, detector="rule_ownership", description=f"Rule {missing} has no ownership entry.", recommendation="Add owner/status/precision/coverage/known_gaps for this rule.", confidence="high"))
    required = {"owner", "status", "precision", "coverage", "known_gaps"}
    for rule_id, entry in sorted(data.items()):
        if not isinstance(entry, dict):
            report.add(Issue(file=str(path), category="rule_ownership.invalid_entry", severity=Severity.HIGH, detector="rule_ownership", description=f"{rule_id} entry must be an object.", recommendation="Use an object with owner/status/precision/coverage/known_gaps.", confidence="high"))
            continue
        for field in sorted(required - set(entry)):
            report.add(Issue(file=str(path), category="rule_ownership.missing_field", severity=Severity.HIGH, detector="rule_ownership", description=f"{rule_id} misses {field}.", recommendation="Complete the rule ownership contract.", confidence="high"))
    return report
