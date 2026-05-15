from __future__ import annotations

from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline


def _analyze(tmp_path):
    return AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False)).analyze_paths([str(tmp_path)])


def test_same_file_shell_wrapper_forwarded_star_args_is_detected(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from subprocess import run\n\n"
        "def shell(*args):\n"
        "    return run(*args, shell=True)\n\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return shell(cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYDF002") and "shell wrapper shell" in issue.description for issue in report.issues)


def test_same_file_shell_wrapper_forwarded_kwargs_is_detected(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from subprocess import run\n\n"
        "def shell(**kwargs):\n"
        "    return run(**kwargs, shell=True)\n\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return shell(args=cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYDF002") and "shell wrapper shell" in issue.description for issue in report.issues)


def test_cross_file_shell_wrapper_forwarded_star_args_is_detected(tmp_path):
    (tmp_path / "shells.py").write_text(
        "from subprocess import run\n\n"
        "def shell(*args):\n"
        "    return run(*args, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from shells import shell\n\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return shell(cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") and "*args shell wrapper shells.shell" in issue.description for issue in report.issues)


def test_cross_file_shell_wrapper_forwarded_kwargs_is_detected(tmp_path):
    (tmp_path / "shells.py").write_text(
        "from subprocess import run\n\n"
        "def shell(**kwargs):\n"
        "    return run(**kwargs, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from shells import shell\n\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return shell(args=cmd)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") and "**kwargs shell wrapper shells.shell" in issue.description for issue in report.issues)
