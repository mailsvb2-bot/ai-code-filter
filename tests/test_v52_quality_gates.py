from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.behavior_audit import audit_behavior
from ai_code_filter.coverage_audit import audit_coverage
from ai_code_filter.mutation_audit import audit_mutation_lite


def _write_basic_project(root: Path, *, weak_test: bool = False) -> None:
    (root / "app.py").write_text(
        "def is_positive(value):\n"
        "    return value > 0\n"
        "\n"
        "def always_true():\n"
        "    return True\n",
        encoding="utf-8",
    )
    tests = root / "tests"
    tests.mkdir()
    if weak_test:
        body = "from app import is_positive\n\ndef test_positive():\n    assert is_positive(1)\n"
    else:
        body = "from app import is_positive, always_true\n\ndef test_positive():\n    assert is_positive(1)\n    assert not is_positive(-1)\n\ndef test_bool():\n    assert always_true() is True\n"
    (tests / "test_app.py").write_text(body, encoding="utf-8")


def test_coverage_audit_reports_budget_failure(tmp_path: Path) -> None:
    _write_basic_project(tmp_path, weak_test=True)
    report, summary = audit_coverage(tmp_path, min_lines=99.0, timeout=60)
    assert summary.tool_available is True
    assert any(issue.category.startswith("COV003") for issue in report.issues)


def test_mutation_lite_detects_surviving_mutant(tmp_path: Path) -> None:
    _write_basic_project(tmp_path, weak_test=True)
    report, summary = audit_mutation_lite(tmp_path, max_mutants=1, timeout=60)
    assert summary.discovered_candidates >= 1
    assert any(issue.category.startswith("MUT010") for issue in report.issues)


def test_behavior_audit_can_disable_command_probes(tmp_path: Path) -> None:
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [{"type": "command", "name": "cmd", "cmd": ["python", "--version"], "expect": {"exit_code": 0}}]}), encoding="utf-8")
    report, summary = audit_behavior(tmp_path, spec=spec, allow_commands=False)
    assert summary.to_dict()["failed"] == 1
    assert any(issue.category.startswith("BEHAVIOR010") for issue in report.issues)


def test_behavior_audit_deny_network_blocks_python_socket(tmp_path: Path) -> None:
    (tmp_path / "netmod.py").write_text(
        "def open_socket():\n"
        "    import socket\n"
        "    socket.socket()\n"
        "    return 'opened'\n",
        encoding="utf-8",
    )
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [{"type": "function", "target": "netmod:open_socket", "expect": {"equals": "opened"}}]}), encoding="utf-8")
    report, summary = audit_behavior(tmp_path, spec=spec, deny_network=True)
    assert summary.to_dict()["failed"] == 1
    assert any("network disabled" in str(issue.evidence) for issue in report.issues)
