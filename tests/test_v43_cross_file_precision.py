from __future__ import annotations

from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline
from ai_code_filter.symbols import build_symbol_table
import ast


def _analyze(tmp_path):
    return AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False)).analyze_paths([str(tmp_path)])


def test_cross_file_shell_wrapper_import_alias_is_detected(tmp_path):
    (tmp_path / "shells.py").write_text(
        "from subprocess import run\n\ndef shell(cmd):\n    return run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import request\nfrom shells import shell as sh\n\ndef handler():\n    cmd = request.args.get('cmd')\n    return sh(cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") and "shells.shell" in issue.description for issue in report.issues)


def test_cross_file_bound_method_shell_wrapper_is_detected_without_sql_false_positive(tmp_path):
    (tmp_path / "shells.py").write_text(
        "from subprocess import run\n\nclass Runner:\n    def execute(self, cmd):\n        return run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import request\nfrom shells import Runner\n\ndef handler():\n    cmd = request.args.get('cmd')\n    runner = Runner()\n    return runner.execute(cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") and "shells.Runner.execute" in issue.description for issue in report.issues)
    assert not any(issue.category.startswith("PYDF001") and issue.location == "runner.execute(cmd)" for issue in report.issues)


def test_symbol_table_resolves_imported_constructor_bound_method_alias():
    tree = ast.parse("from shells import Runner\nrunner = Runner()\nrunner.execute('x')\n")
    symbols = build_symbol_table(tree)
    call = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and getattr(node, "lineno", None) == 3][0]
    resolved = symbols.resolve_call(call)
    assert resolved.canonical == "shells.Runner.execute"
    assert "runner->shells.Runner" in resolved.evidence
