from __future__ import annotations

import json
from pathlib import Path

from .rules.catalog import RuleCatalog


ANALYZER_CAPABILITIES = [
    {"rule_id": "PYDF001", "title": "Data-flow SQL injection", "severity": "CRITICAL", "language": "python", "category": "Data flow", "detector": "python_dataflow"},
    {"rule_id": "PYDF002", "title": "Data-flow command injection", "severity": "CRITICAL", "language": "python", "category": "Data flow", "detector": "python_dataflow"},
    {"rule_id": "PYDF003", "title": "Data-flow template injection", "severity": "HIGH", "language": "python", "category": "Data flow", "detector": "python_dataflow"},
    {"rule_id": "PYXDF001", "title": "Cross-file SQL injection", "severity": "CRITICAL", "language": "python", "category": "Cross-file data flow", "detector": "python_cross_file_dataflow"},
    {"rule_id": "PYXDF002", "title": "Cross-file command injection", "severity": "CRITICAL", "language": "python", "category": "Cross-file data flow", "detector": "python_cross_file_dataflow"},
    {"rule_id": "PYXDF003", "title": "Cross-file template/HTML injection", "severity": "HIGH", "language": "python", "category": "Cross-file data flow", "detector": "python_cross_file_dataflow"},
    {"rule_id": "JSSTR001", "title": "postMessage wildcard target", "severity": "HIGH", "language": "javascript", "category": "Browser security", "detector": "javascript_structure"},
    {"rule_id": "JSSTR002", "title": "message listener without origin check", "severity": "HIGH", "language": "javascript", "category": "Browser security", "detector": "javascript_structure"},
    {"rule_id": "JSSTR003", "title": "URL parameter redirect sink", "severity": "MEDIUM", "language": "javascript", "category": "Browser security", "detector": "javascript_structure"},
    {"rule_id": "JSSTR004", "title": "String timer execution", "severity": "HIGH", "language": "javascript", "category": "Browser security", "detector": "javascript_structure"},
    {"rule_id": "JSSTR005", "title": "URL parameter window.open sink", "severity": "MEDIUM", "language": "javascript", "category": "Browser security", "detector": "javascript_structure"},
    {"rule_id": "JSSTR006", "title": "document.domain relaxation", "severity": "HIGH", "language": "javascript", "category": "Browser security", "detector": "javascript_structure"},
    {"rule_id": "JSSTR007", "title": "DOM XSS parameter-to-HTML sink", "severity": "HIGH", "language": "javascript", "category": "Browser security", "detector": "javascript_structure"},

    {"rule_id": "ARR001", "title": "Duplicate scalar array entries", "severity": "MEDIUM", "language": "multi", "category": "Array ambiguity", "detector": "array_ambiguity"},
    {"rule_id": "ARR002", "title": "Duplicate array pair keys", "severity": "HIGH", "language": "multi", "category": "Array ambiguity", "detector": "array_ambiguity"},
    {"rule_id": "ARR003", "title": "Duplicate registry identifiers", "severity": "HIGH", "language": "multi", "category": "Array ambiguity", "detector": "array_ambiguity"},
    {"rule_id": "ARR004", "title": "Conflicting allow/deny array policy entries", "severity": "CRITICAL", "language": "multi", "category": "Array ambiguity", "detector": "array_ambiguity"},
    {"rule_id": "ARR005", "title": "Wildcard array rule before specific rule", "severity": "MEDIUM", "language": "multi", "category": "Array ambiguity", "detector": "array_ambiguity"},
    {"rule_id": "ARR006", "title": "Duplicate JavaScript dispatch array keys", "severity": "HIGH", "language": "javascript", "category": "Array ambiguity", "detector": "array_ambiguity"},
    {"rule_id": "ARR008", "title": "Contradictory boolean flags in registry arrays", "severity": "HIGH", "language": "multi", "category": "Array ambiguity", "detector": "array_ambiguity"},

    {"rule_id": "CAP001", "title": "Unified capability registry", "severity": "MEDIUM", "language": "multi", "category": "Architecture", "detector": "capability_registry"},
    {"rule_id": "FUZZ001", "title": "Property-style path/manifest fuzz acceptance", "severity": "HIGH", "language": "multi", "category": "Fuzzing", "detector": "fuzz_suite"},
    {"rule_id": "MASS001", "title": "Architecture mass and suite-sprawl audit", "severity": "MEDIUM", "language": "multi", "category": "Architecture", "detector": "mass_audit"},
    {"rule_id": "DEP001", "title": "Dependency manifest consistency audit", "severity": "HIGH", "language": "multi", "category": "Dependencies", "detector": "dependency_audit"},
]


def _increment(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def coverage_matrix(catalog: RuleCatalog) -> dict:
    rules = []
    by_language: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    deterministic_by_language: dict[str, int] = {}
    deterministic_by_severity: dict[str, int] = {}
    for rule in catalog.rules:
        item = {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "severity": rule.severity.value,
            "language": rule.language,
            "category": rule.category,
            "rationale": rule.rationale,
            "detector": "deterministic",
        }
        rules.append(item)
        _increment(deterministic_by_language, rule.language)
        _increment(deterministic_by_severity, rule.severity.value)
        _increment(by_language, rule.language)
        _increment(by_category, rule.category)
        _increment(by_severity, rule.severity.value)
    for capability in ANALYZER_CAPABILITIES:
        _increment(by_language, capability["language"])
        _increment(by_category, capability["category"])
        _increment(by_severity, capability["severity"])
    return {
        "total_rules": len(rules),
        "total_capabilities": len(rules) + len(ANALYZER_CAPABILITIES),
        "by_language": by_language,
        "by_category": by_category,
        "by_severity": by_severity,
        "deterministic_by_language": deterministic_by_language,
        "deterministic_by_severity": deterministic_by_severity,
        "rules": rules,
        "analyzer_capabilities": ANALYZER_CAPABILITIES,
    }


def write_coverage_matrix(catalog: RuleCatalog, output: str | None) -> None:
    """Write a JSON coverage matrix when output is provided; returns None."""
    if not output:
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(coverage_matrix(catalog), ensure_ascii=False, indent=2), encoding="utf-8")
