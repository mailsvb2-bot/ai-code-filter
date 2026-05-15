from __future__ import annotations

from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline


def _analyze(tmp_path):
    return AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False)).analyze_paths([str(tmp_path)])


def test_same_file_shell_wrapper_tainted_default_argument_is_detected(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "from subprocess import run\n\n"
        "def shell(command=os.getenv('CMD')):\n"
        "    return run(command, shell=True)\n\n"
        "def handler():\n"
        "    return shell()\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYDF002") and "default" in issue.description for issue in report.issues)


def test_same_file_default_passthrough_reaches_shell_sink(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\n"
        "from subprocess import run\n\n"
        "def get_cmd(command=os.getenv('CMD')):\n"
        "    return command\n\n"
        "def handler():\n"
        "    cmd = get_cmd()\n"
        "    return run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYDF002") for issue in report.issues)


def test_cross_file_shell_wrapper_tainted_default_argument_is_detected(tmp_path):
    (tmp_path / "shells.py").write_text(
        "import os\n"
        "from subprocess import run\n\n"
        "def shell(command=os.getenv('CMD')):\n"
        "    return run(command, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from shells import shell\n\n"
        "def handler():\n"
        "    return shell()\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") and "default" in issue.description for issue in report.issues)


def test_cross_file_default_passthrough_reaches_shell_sink(tmp_path):
    (tmp_path / "helpers.py").write_text(
        "import os\n\n"
        "def get_cmd(command=os.getenv('CMD')):\n"
        "    return command\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from subprocess import run\n"
        "from helpers import get_cmd\n\n"
        "def handler():\n"
        "    cmd = get_cmd()\n"
        "    return run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    report = _analyze(tmp_path)
    assert any(issue.category.startswith("PYXDF002") for issue in report.issues)
