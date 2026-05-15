from __future__ import annotations

from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline


def _analyze(tmp_path):
    return AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False)).analyze_paths([str(tmp_path)])


def test_same_file_shell_wrapper_keyword_argument_is_detected(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from subprocess import run\n\n"
        "def shell(command):\n"
        "    return run(command, shell=True)\n\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return shell(command=cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYDF002") and "shell wrapper shell" in issue.description for issue in report.issues)


def test_cross_file_shell_wrapper_keyword_argument_is_detected(tmp_path):
    (tmp_path / "shells.py").write_text(
        "from subprocess import run\n\n"
        "def shell(command):\n"
        "    return run(command, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from shells import shell\n\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return shell(command=cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") and "shells.shell" in issue.description for issue in report.issues)


def test_cross_file_return_param_keyword_source_reaches_shell_sink(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "def passthrough(value):\n"
        "    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from subprocess import run\n"
        "from helpers import passthrough\n\n"
        "def handler():\n"
        "    cmd = passthrough(value=request.args.get('cmd'))\n"
        "    return run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") and issue.file == "app.py" for issue in report.issues)
