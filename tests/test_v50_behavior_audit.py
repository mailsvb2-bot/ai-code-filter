from __future__ import annotations

import json
import sys
from pathlib import Path

from ai_code_filter.behavior_audit import audit_behavior
from ai_code_filter.cli import main


def test_behavior_audit_function_contract_success(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [{"type": "function", "name": "add", "target": "app:add", "args": [2, 3], "expect": {"equals": 5}}]}), encoding="utf-8")

    report, summary = audit_behavior(tmp_path, spec=spec)

    assert report.summary()["TOTAL"] == 0
    assert summary.to_dict()["passed"] == 1


def test_behavior_audit_function_contract_failure(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [{"type": "function", "name": "add", "target": "app:add", "args": [2, 3], "expect": {"equals": 5}}]}), encoding="utf-8")

    report, summary = audit_behavior(tmp_path, spec=spec)

    assert summary.to_dict()["failed"] == 1
    assert any(issue.category.startswith("BEHAVIOR010") for issue in report.issues)


def test_behavior_audit_expected_exception_contract(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def parse(value):\n    if not value:\n        raise ValueError('empty')\n    return value\n", encoding="utf-8")
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [{"type": "function", "target": "app:parse", "args": [""], "expect": {"raises": "ValueError"}}]}), encoding="utf-8")

    report, summary = audit_behavior(tmp_path, spec=spec)

    assert report.summary()["TOTAL"] == 0
    assert summary.to_dict()["passed"] == 1


def test_behavior_audit_command_contract_and_summary_json(tmp_path: Path) -> None:
    script = tmp_path / "tool.py"
    script.write_text("print('ready')\n", encoding="utf-8")
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [{"type": "command", "cmd": [sys.executable, str(script)], "expect": {"exit_code": 0, "stdout_contains": "ready"}}]}), encoding="utf-8")
    summary = tmp_path / "summary.json"

    code = main(["behavior-audit", str(tmp_path), "--spec", str(spec), "--summary-json", str(summary), "--ci"])

    assert code == 0
    data = json.loads(summary.read_text(encoding="utf-8"))
    assert data["behavior"]["passed"] == 1


def test_behavior_audit_no_spec_is_blocking(tmp_path: Path) -> None:
    report, summary = audit_behavior(tmp_path)

    assert summary.to_dict()["total"] == 0
    assert any(issue.category.startswith("BEHAVIOR001") for issue in report.issues)


def test_behavior_audit_import_smoke(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "core.py").write_text("VALUE = 1\n", encoding="utf-8")

    report, summary = audit_behavior(tmp_path, import_smoke=True)

    assert report.summary()["TOTAL"] == 0
    assert summary.to_dict()["passed"] >= 1


def test_behavior_audit_strict_sandbox_cli_bundles_safety_flags(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("STRICT_SANDBOX_TOKEN", "leaked")
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def token_visible():\n"
        "    return os.environ.get('STRICT_SANDBOX_TOKEN')\n"
        "def open_socket():\n"
        "    import socket\n"
        "    socket.socket()\n"
        "    return 'opened'\n",
        encoding="utf-8",
    )
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [
        {"type": "function", "name": "token stripped", "target": "app:token_visible", "expect": {"equals": None}},
        {"type": "function", "name": "socket blocked", "target": "app:open_socket", "expect": {"raises": "RuntimeError"}},
        {"type": "command", "name": "command disabled", "cmd": [sys.executable, "--version"], "expect": {"exit_code": 0}},
    ]}), encoding="utf-8")

    code = main(["behavior-audit", str(tmp_path), "--spec", str(spec), "--strict-sandbox", "--ci"])

    assert code == 1
