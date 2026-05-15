from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from ai_code_filter.artifacts import html_report, junit_xml, markdown_report, sarif_dict
from ai_code_filter.models import Issue, Report, Severity


def sample_report() -> Report:
    report = Report()
    report.add(Issue(file="app.py", category="PY002: Security", severity=Severity.CRITICAL, detector="rule_catalog", description="Unsafe eval.", recommendation="Remove eval.", location="eval(x)", line_number=10))
    return report


def test_sarif_export_shape():
    data = sarif_dict(sample_report())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "PY002"
    json.dumps(data)


def test_junit_export_is_xml():
    root = ET.fromstring(junit_xml(sample_report()))
    assert root.tag == "testsuite"
    assert root.attrib["failures"] == "1"
    assert root.find("testcase/failure") is not None


def test_markdown_and_html_exports_escape_content():
    md = markdown_report(sample_report())
    html = html_report(sample_report())
    assert "AI Code Filter Report" in md
    assert "<!doctype html>" in html
    assert "&lt;" not in markdown_report(Report())


def test_cli_writes_all_report_formats(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("eval(user_code)\n", encoding="utf-8")
    from ai_code_filter.cli import main

    out_json = tmp_path / "report.json"
    out_sarif = tmp_path / "report.sarif"
    out_junit = tmp_path / "report.xml"
    out_md = tmp_path / "report.md"
    out_html = tmp_path / "report.html"
    code = main([
        "analyze", str(source), "--no-ai", "--output", str(out_json), "--sarif", str(out_sarif), "--junit", str(out_junit), "--markdown", str(out_md), "--html", str(out_html)
    ])
    assert code == 0
    assert all(p.exists() for p in [out_json, out_sarif, out_junit, out_md, out_html])
