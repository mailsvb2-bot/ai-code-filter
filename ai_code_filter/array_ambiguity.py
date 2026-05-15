from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .analyzers.array_ambiguity import ArrayAmbiguityAnalyzer
from .models import FilePayload, Issue, Report, Severity


def _payload(path: Path, root: Path) -> FilePayload:
    return FilePayload(path=path, project_root=root, content=path.read_text(encoding="utf-8"))


def _case_issue(case_id: str, observed_categories: list[str]) -> Issue:
    return Issue(
        file=f"<array-ambiguity:{case_id}>",
        category="ARRSUITE001: Array ambiguity fixture failure",
        severity=Severity.HIGH,
        detector="array_ambiguity_suite",
        description=f"Array ambiguity fixture did not trigger expected detector. Observed categories: {observed_categories}",
        recommendation="Fix ArrayAmbiguityAnalyzer or update the fixture expectation deliberately.",
    )


def _run_code_case(root: Path, case_id: str, filename: str, source: str, expected_prefixes: tuple[str, ...]) -> tuple[list[str], list[Issue]]:
    case_dir = root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    path = case_dir / filename
    path.write_text(source, encoding="utf-8")
    report = Report()
    try:
        issues = ArrayAmbiguityAnalyzer().analyze(_payload(path, case_dir))
    except Exception as exc:
        report.add(Issue(file=f"<array-ambiguity:{case_id}>", category="ARRSUITE002: Array ambiguity fixture crash", severity=Severity.HIGH, detector="array_ambiguity_suite", description=f"Fixture crashed: {exc}", recommendation="Fix analyzer crash."))
        return [], list(report.issues)
    categories = [i.category.split(":", 1)[0] for i in issues]
    if expected_prefixes and not any(cat in expected_prefixes for cat in categories):
        report.add(_case_issue(case_id, categories))
    return categories, list(report.issues)


def array_ambiguity_cases() -> list[dict[str, object]]:
    return [
        {"case_id": "python_duplicate_scalars", "family": "scalar_duplicates", "language": "python", "expected": ("ARR001",), "filename": "case.py", "source": "commands = ['start', 'pay', 'start']\n"},
        {"case_id": "python_duplicate_pair_keys", "family": "pair_keys", "language": "python", "expected": ("ARR002",), "filename": "case.py", "source": "handlers = [('start', start), ('start', legacy)]\n"},
        {"case_id": "python_duplicate_dict_route", "family": "registry_ids", "language": "python", "expected": ("ARR003",), "filename": "case.py", "source": "routes = [{'route': '/start', 'handler': 'a'}, {'route': '/start', 'handler': 'b'}]\n"},
        {"case_id": "python_allow_deny_conflict", "family": "policy_conflicts", "language": "python", "expected": ("ARR004",), "filename": "case.py", "source": "policies = [{'subject':'admin','action':'write','resource':'orders','effect':'allow'}, {'subject':'admin','action':'write','resource':'orders','effect':'deny'}]\n"},
        {"case_id": "python_wildcard_before_specific", "family": "ordering", "language": "python", "expected": ("ARR005",), "filename": "case.py", "source": "rules = [{'route': '*', 'handler': 'fallback'}, {'route': '/pay', 'handler': 'pay'}]\n"},
        {"case_id": "python_boolean_contradiction", "family": "boolean_conflicts", "language": "python", "expected": ("ARR008",), "filename": "case.py", "source": "features = [{'id': 'checkout', 'enabled': True}, {'id': 'checkout', 'enabled': False}]\n"},
        {"case_id": "json_duplicate_ids", "family": "json_registry", "language": "json", "expected": ("ARR003",), "filename": "case.json", "source": '{"plugins": [{"id":"pay"}, {"id":"pay"}]}'},
        {"case_id": "json_duplicate_scalars", "family": "json_scalars", "language": "json", "expected": ("ARR001",), "filename": "case.json", "source": '{"roles": ["admin", "user", "admin"]}'},
        {"case_id": "js_duplicate_pair_keys", "family": "js_pairs", "language": "javascript", "expected": ("ARR006",), "filename": "case.js", "source": "const handlers = [['start', startHandler], ['start', legacyHandler]];\n"},
        {"case_id": "js_duplicate_routes", "family": "js_registry", "language": "javascript", "expected": ("ARR003",), "filename": "case.js", "source": "const routes = [{route: '/pay', handler: pay}, {route: '/pay', handler: oldPay}];\n"},
        {"case_id": "valid_unique_arrays", "family": "false_positive_guard", "language": "python", "expected": (), "filename": "case.py", "source": "routes = [{'route': '/start'}, {'route': '/pay'}]\nroles = ['admin', 'user']\n"},
    ]


def run_array_ambiguity_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-array-ambiguity-") as tmp_s:
        root = Path(tmp_s)
        for case in array_ambiguity_cases():
            categories, issues = _run_code_case(root, str(case["case_id"]), str(case["filename"]), str(case["source"]), tuple(case["expected"]))
            expected = tuple(case["expected"])
            if not expected and categories:
                report.add(Issue(file=f"<array-ambiguity:{case['case_id']}>", category="ARRSUITE003: Array ambiguity false positive", severity=Severity.HIGH, detector="array_ambiguity_suite", description=f"False-positive guard produced categories: {categories}", recommendation="Refine ArrayAmbiguityAnalyzer false-positive controls."))
            report.extend(issues)
    return report


def array_ambiguity_suite_summary() -> dict[str, object]:
    cases = array_ambiguity_cases()
    by_family: dict[str, int] = {}
    by_language: dict[str, int] = {}
    for case in cases:
        by_family[str(case["family"])] = by_family.get(str(case["family"]), 0) + 1
        by_language[str(case["language"])] = by_language.get(str(case["language"]), 0) + 1
    return {
        "suite": "array_ambiguity",
        "case_count": len(cases),
        "by_family": dict(sorted(by_family.items())),
        "by_language": dict(sorted(by_language.items())),
        "threat_classes": [
            "duplicate_scalar_array_entries",
            "duplicate_array_pair_keys",
            "duplicate_registry_identifiers",
            "conflicting_allow_deny_policy_entries",
            "wildcard_before_specific_ordering",
            "contradictory_boolean_flags",
            "json_registry_ambiguity",
            "javascript_dispatch_array_ambiguity",
        ],
        "cases": [
            {"case_id": c["case_id"], "family": c["family"], "language": c["language"], "expected_prefixes": list(c["expected"])}
            for c in cases
        ],
    }


def write_array_ambiguity_summary(path: str | Path | None) -> None:
    """Write the array-ambiguity fixture inventory; returns None when no path is supplied."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(array_ambiguity_suite_summary(), ensure_ascii=False, indent=2), encoding="utf-8")
