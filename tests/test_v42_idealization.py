from __future__ import annotations

import json

from ai_code_filter.cli import main
from ai_code_filter.config import RuntimeConfig
from ai_code_filter.fix_suggestions import build_fix_suggestions
from ai_code_filter.pipeline import AnalysisPipeline
from ai_code_filter.symbols import build_symbol_table
import ast


def test_symbol_table_resolves_constructor_bound_method_alias():
    tree = ast.parse('''
class Runner:
    def execute(self, cmd):
        pass
runner = Runner()
runner.execute("ls")
''')
    symbols = build_symbol_table(tree)
    call = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n, 'lineno', None) == 6][0]
    resolved = symbols.resolve_call(call)
    assert resolved.canonical == "Runner.execute"
    assert "runner->Runner" in resolved.evidence


def test_python_dataflow_detects_bound_method_shell_wrapper(tmp_path):
    src = tmp_path / "app.py"
    src.write_text('''
from subprocess import run

class Runner:
    def execute(self, cmd):
        return run(cmd, shell=True)

def handler(request):
    cmd = request.args.get("cmd")
    runner = Runner()
    return runner.execute(cmd)
''', encoding="utf-8")
    report = AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False)).analyze_paths([str(tmp_path)])
    assert any(issue.category.startswith("PYDF002") and "shell wrapper" in issue.description for issue in report.issues)


def test_fix_suggestions_are_review_only_for_security_findings():
    data = {
        "issues": [
            {
                "file": "app.py",
                "line_number": 10,
                "category": "PY008: HTTP request without timeout",
                "confidence": "high",
                "location": "requests.get(url)",
                "evidence": {"callsite": "requests.get(url)"},
            },
            {"file": "app.py", "category": "PYDF002: Data-flow command injection", "confidence": "high"},
        ]
    }
    suggestions = build_fix_suggestions(data)
    assert suggestions["count"] == 2
    assert all(item["mode"] == "review_only" for item in suggestions["suggestions"])
    assert all(item["safe_to_apply_automatically"] is False for item in suggestions["suggestions"])


def test_cli_performance_budget_and_suggest_fixes(tmp_path, capsys):
    assert main(["performance-budget", "--files", "3", "--max-seconds", "30", "--ci"]) == 0
    out = capsys.readouterr().out
    assert '"files": 3' in out
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"issues": [{"file": "a.py", "category": "PY007: Unsafe yaml.load", "confidence": "high"}]}), encoding="utf-8")
    assert main(["suggest-fixes", str(report)]) == 0
    assert "replace_yaml_load" in capsys.readouterr().out
