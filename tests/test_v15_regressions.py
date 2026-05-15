from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from ai_code_filter import __version__
from ai_code_filter.artifacts import junit_xml, markdown_report, sarif_dict
from ai_code_filter.assistant.capabilities import assistant_capability_matrix
from ai_code_filter.assistant.patch_plan import build_patch_plan
from ai_code_filter.assistant.review_plan import build_review_plan
from ai_code_filter.cli import main
from ai_code_filter.coverage import coverage_matrix
from ai_code_filter.models import Issue, Report, Severity
from ai_code_filter.rules import build_default_catalog


def incomplete_report() -> Report:
    report = Report()
    report.record_skip("<pyright>", "pyright executable not found")
    report.record_skip("<mypy>", "mypy executable not found")
    report.record_failure("bad.py", RuntimeError("boom"))
    return report


def test_package_version_and_capability_matrix_match():
    assert __version__ == "0.59.0"
    assert assistant_capability_matrix()["version"] == __version__


def test_junit_counts_include_skipped_and_failed_files():
    root = ET.fromstring(junit_xml(incomplete_report()))
    assert root.attrib["tests"] == "4"
    assert root.attrib["failures"] == "1"
    assert root.attrib["errors"] == "1"
    assert root.attrib["skipped"] == "2"
    assert root.findall("testcase/skipped")
    assert root.findall("testcase/error")


def test_markdown_lists_skipped_and_failed_details():
    md = markdown_report(incomplete_report())
    assert "## Failed files" in md
    assert "bad.py" in md
    assert "## Skipped files" in md
    assert "<pyright>" in md


def test_sarif_has_invocation_notifications_for_incomplete_analysis():
    sarif = sarif_dict(incomplete_report())
    notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("bad.py" in note["message"]["text"] for note in notifications)
    assert any("<pyright>" in note["message"]["text"] for note in notifications)


def test_assistant_outputs_create_nested_directories(tmp_path: Path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"issues": [], "failed_files": [], "skipped_files": []}), encoding="utf-8")
    assert main(["assistant-capabilities", "--output", str(tmp_path / "nested" / "caps.json")]) == 0
    assert main(["prompt-pack", "--output", str(tmp_path / "nested" / "prompts.json")]) == 0
    assert main(["explain-report", str(report), "--output", str(tmp_path / "nested" / "review.md")]) == 0
    assert main(["review-plan", str(report), "--output", str(tmp_path / "nested" / "plan.json")]) == 0
    assert main(["patch-plan", str(report), "--output", str(tmp_path / "nested" / "patch.json")]) == 0
    assert (tmp_path / "nested" / "caps.json").exists()
    assert (tmp_path / "nested" / "patch.json").exists()


def test_inspect_deps_creates_nested_output(tmp_path: Path):
    target = tmp_path / "out" / "deps.json"
    assert main(["inspect-deps", str(tmp_path), "--output", str(target)]) == 0
    assert target.exists()


def test_type_check_ci_fails_when_tools_are_skipped(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("ai_code_filter.type_resolution.type_tools.shutil.which", lambda _: None)
    assert main(["type-check", str(tmp_path), "--ci"]) == 1


def test_review_plan_uses_computed_summary_when_summary_missing():
    report = {"issues": [{"severity": "CRITICAL", "detector": "rule_catalog", "file": "x.py"}], "failed_files": [], "skipped_files": [{"file": "<mypy>", "reason": "missing"}]}
    plan = build_review_plan(report)
    assert plan["counts"]["summary"]["CRITICAL"] == 1
    assert plan["counts"]["summary"]["SKIPPED_FILES"] == 1
    assert plan["maturity_score"] < 100
    assert any("skipped" in risk.lower() for risk in plan["risks"])


def test_patch_plan_contains_incomplete_analysis_items():
    report = {"issues": [], "failed_files": [{"file": "bad.py", "error": "boom"}], "skipped_files": [{"file": "<pyright>", "reason": "missing"}]}
    plan = build_patch_plan(report)
    assert any(item["file"] == "bad.py" for item in plan["items"])
    assert any(item["file"] == "<pyright>" for item in plan["items"])


def test_coverage_counts_include_analyzer_capabilities():
    matrix = coverage_matrix(build_default_catalog())
    assert matrix["total_capabilities"] == len(matrix["rules"]) + len(matrix["analyzer_capabilities"])
    assert sum(matrix["by_language"].values()) == matrix["total_capabilities"]
    assert sum(matrix["by_severity"].values()) == matrix["total_capabilities"]


def test_junit_normal_report_still_has_one_failure():
    report = Report()
    report.add(Issue(file="app.py", category="PY002: Security", severity=Severity.CRITICAL, detector="rule_catalog", description="Unsafe eval.", recommendation="Remove eval."))
    root = ET.fromstring(junit_xml(report))
    assert root.attrib["tests"] == "1"
    assert root.attrib["failures"] == "1"
