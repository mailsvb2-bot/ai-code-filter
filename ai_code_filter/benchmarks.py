from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analyzers.rule_catalog import RuleCatalogAnalyzer
from .analyzers.python_dataflow import PythonDataFlowAnalyzer
from .analyzers.python_cross_file_dataflow import PythonCrossFileDataFlowAnalyzer
from .analyzers.javascript_structure import JavaScriptStructureAnalyzer
from .models import FilePayload


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    filename: str
    source: str
    expected_present: tuple[str, ...] = ()
    expected_absent: tuple[str, ...] = ()


@dataclass(frozen=True)
class MultiFileBenchmarkCase:
    name: str
    files: dict[str, str]
    target_filename: str
    expected_present: tuple[str, ...] = ()
    expected_absent: tuple[str, ...] = ()


def built_in_cases() -> tuple[BenchmarkCase, ...]:
    return (
        BenchmarkCase(
            name="python_sql_taint_positive",
            filename="app.py",
            source='''
def handler(request, conn):
    user_id = request.args.get("id")
    conn.execute(f"select * from users where id={user_id}")
''',
            expected_present=("PYDF001",),
        ),
        BenchmarkCase(
            name="python_interfunction_sql_taint_positive",
            filename="inter.py",
            source='''
def get_id(request):
    return request.args.get("id")

def handler(request, conn):
    user_id = get_id(request)
    conn.execute(f"select * from users where id={user_id}")
''',
            expected_present=("PYDF001",),
        ),
        BenchmarkCase(
            name="python_safe_parameterized_sql_negative",
            filename="safe.py",
            source='''
def handler(request, conn):
    user_id = request.args.get("id")
    conn.execute("select * from users where id=%s", (user_id,))
''',
            expected_absent=("PYDF001",),
        ),
        BenchmarkCase(
            name="python_template_sanitized_negative",
            filename="html_safe.py",
            source='''
from markupsafe import escape
from flask import render_template_string

def handler(request):
    page = request.args.get("page")
    return render_template_string(escape(page))
''',
            expected_absent=("PYDF003",),
        ),
        BenchmarkCase(
            name="javascript_message_listener_positive",
            filename="app.js",
            source='''
window.addEventListener("message", (event) => {
  handle(event.data)
})
other.postMessage(payload, "*")
''',
            expected_present=("JSSTR001", "JSSTR002"),
        ),
        BenchmarkCase(
            name="javascript_message_listener_negative",
            filename="safe.js",
            source='''
window.addEventListener("message", (event) => {
  if (event.origin !== "https://example.com") return
  handle(event.data)
})
other.postMessage(payload, "https://example.com")
''',
            expected_absent=("JSSTR001", "JSSTR002"),
        ),
        BenchmarkCase(
            name="javascript_dom_xss_positive",
            filename="dom.js",
            source='''
const html = localStorage.getItem("html")
container.innerHTML = html
''',
            expected_present=("JSSTR007",),
        ),
    )


def built_in_multifile_cases() -> tuple[MultiFileBenchmarkCase, ...]:
    return (
        MultiFileBenchmarkCase(
            name="python_cross_file_sql_wrapper_positive",
            files={
                "web.py": "from flask import request\n\ndef current_id():\n    return request.args.get('id')\n",
                "db.py": "def run_query(q, cursor):\n    cursor.execute(q)\n",
                "app.py": "from web import current_id\nfrom db import run_query\n\ndef handler(cursor):\n    value = current_id()\n    run_query('select * from users where id=' + value, cursor)\n",
            },
            target_filename="app.py",
            expected_present=("PYXDF001",),
        ),
        MultiFileBenchmarkCase(
            name="python_cross_file_sanitized_negative",
            files={
                "web.py": "from flask import request\n\ndef current_id():\n    return request.args.get('id')\n",
                "db.py": "def run_query(q, cursor):\n    cursor.execute(q)\n",
                "app.py": "from markupsafe import escape\nfrom web import current_id\nfrom db import run_query\n\ndef handler(cursor):\n    value = escape(current_id())\n    run_query('select * from users where id=' + value, cursor)\n",
            },
            target_filename="app.py",
            expected_absent=("PYXDF001",),
        ),
    )


def _score_case(name: str, found: set[str], expected_present: tuple[str, ...], expected_absent: tuple[str, ...]) -> tuple[dict[str, Any], int, int, int, int]:
    present_ok = sorted(rule for rule in expected_present if rule in found)
    missing = sorted(rule for rule in expected_present if rule not in found)
    absent_ok = sorted(rule for rule in expected_absent if rule not in found)
    unexpected = sorted(rule for rule in expected_absent if rule in found)
    return ({
        "case": name,
        "found": sorted(found),
        "expected_present": list(expected_present),
        "expected_absent": list(expected_absent),
        "missing": missing,
        "unexpected": unexpected,
        "passed": not missing and not unexpected,
    }, len(present_ok), len(unexpected), len(missing), len(absent_ok))


def run_built_in_benchmark() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    tp = fp = fn = tn = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        single_analyzers = [RuleCatalogAnalyzer(), PythonDataFlowAnalyzer(), JavaScriptStructureAnalyzer()]
        for case in built_in_cases():
            path = root / case.filename
            path.write_text(case.source, encoding="utf-8")
            payload = FilePayload(path=path, project_root=root, content=case.source)
            issues = []
            for analyzer in single_analyzers:
                issues.extend(analyzer.analyze(payload))
            found = {issue.category.split(":", 1)[0] for issue in issues}
            row, add_tp, add_fp, add_fn, add_tn = _score_case(case.name, found, case.expected_present, case.expected_absent)
            rows.append(row); tp += add_tp; fp += add_fp; fn += add_fn; tn += add_tn

        for case in built_in_multifile_cases():
            payloads: list[FilePayload] = []
            for filename, source in case.files.items():
                path = root / case.name / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
                payloads.append(FilePayload(path=path, project_root=path.parent, content=source))
            target = next(payload for payload in payloads if payload.path.name == case.target_filename)
            analyzer = PythonCrossFileDataFlowAnalyzer(payloads)
            issues = analyzer.analyze(target)
            found = {issue.category.split(":", 1)[0] for issue in issues}
            row, add_tp, add_fp, add_fn, add_tn = _score_case(case.name, found, case.expected_present, case.expected_absent)
            rows.append(row); tp += add_tp; fp += add_fp; fn += add_fn; tn += add_tn

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    specificity = tn / (tn + fp) if tn + fp else 1.0
    return {
        "cases": rows,
        "metrics": {
            "case_count": len(rows),
            "true_positive_expectations": tp,
            "false_positive_expectations": fp,
            "false_negative_expectations": fn,
            "true_negative_expectations": tn,
            "precision_on_expectations": precision,
            "recall_on_expectations": recall,
            "specificity_on_expectations": specificity,
        },
        "passed": all(row["passed"] for row in rows),
    }


def write_benchmark_report(output: str | None = None) -> dict[str, Any]:
    report = run_built_in_benchmark()
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
