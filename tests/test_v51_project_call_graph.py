from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.project_call_graph import build_project_call_graph
from ai_code_filter.analyzers.python_cross_file_dataflow import PythonCrossFileDataFlowAnalyzer
from ai_code_filter.models import FilePayload


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_call_graph_resolves_cross_file_service_to_shell_sink(tmp_path: Path) -> None:
    _write(tmp_path / "shells.py", "from subprocess import run\n\ndef shell(command):\n    return run(command, shell=True)\n")
    _write(
        tmp_path / "service.py",
        "from shells import shell\n\ndef execute(value):\n    return shell(value)\n",
    )
    _write(
        tmp_path / "api.py",
        "from service import execute\n\ndef endpoint(request):\n    cmd = request.args.get('cmd')\n    return execute(cmd)\n",
    )

    graph = build_project_call_graph([str(tmp_path)])
    data = graph.to_dict()
    edge_pairs = {(edge["caller"], edge["callee"]) for edge in data["edges"]}

    assert ("api.endpoint", "service.execute") in edge_pairs
    assert ("service.execute", "shells.shell") in edge_pairs
    assert any(edge["callee"] == "subprocess.run" for edge in data["edges"])
    assert data["summary"]["edges"] >= 3


def test_call_graph_tracks_constructor_type_and_bound_method(tmp_path: Path) -> None:
    _write(tmp_path / "runner.py", "from subprocess import run\n\nclass Runner:\n    def execute(self, command):\n        return run(command, shell=True)\n")
    _write(tmp_path / "api.py", "from runner import Runner\n\ndef endpoint(request):\n    runner = Runner()\n    return runner.execute(request.args.get('cmd'))\n")

    graph = build_project_call_graph([str(tmp_path)])
    edge_pairs = {(edge.caller, edge.callee) for edge in graph.edges}

    assert ("api.endpoint", "runner.Runner") in edge_pairs
    assert ("api.endpoint", "runner.Runner.execute") in edge_pairs


def test_call_graph_cli_writes_json(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "def helper():\n    return 1\n\ndef main():\n    return helper()\n")
    output = tmp_path / "callgraph.json"

    code = main(["call-graph", str(tmp_path), "--output", str(output), "--ci", "--max-unknown-ratio", "1.0"])

    assert code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["nodes"] >= 2
    assert any(edge["caller"] == "app.main" and edge["callee"] == "app.helper" for edge in data["edges"])
    assert "limitations" in data


def test_call_graph_unknown_ratio_budget_can_fail(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "def main(name):\n    return getattr(object(), name)()\n")
    output = tmp_path / "callgraph.json"

    code = main(["call-graph", str(tmp_path), "--output", str(output), "--ci", "--max-unknown-ratio", "0.0"])

    assert code == 1


def test_cross_file_finding_contains_call_and_taint_path_evidence(tmp_path: Path) -> None:
    _write(tmp_path / "shells.py", "from subprocess import run\n\ndef shell(command):\n    return run(command, shell=True)\n")
    _write(tmp_path / "app.py", "from shells import shell\n\ndef handler(request):\n    cmd = request.args.get('cmd')\n    return shell(cmd)\n")
    payloads = [FilePayload(path=p, project_root=tmp_path, content=p.read_text(encoding="utf-8")) for p in sorted(tmp_path.glob("*.py"))]
    analyzer = PythonCrossFileDataFlowAnalyzer(payloads)
    app_payload = next(payload for payload in payloads if payload.path.name == "app.py")

    issues = analyzer.analyze(app_payload)

    assert any(issue.category.startswith("PYXDF002") for issue in issues)
    issue = next(issue for issue in issues if issue.category.startswith("PYXDF002"))
    assert issue.evidence is not None
    assert "call_path" in issue.evidence
    assert "shells.shell" in issue.evidence["call_path"]
    assert "taint_path" in issue.evidence
