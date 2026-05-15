from __future__ import annotations

import xml.etree.ElementTree as ET

from ai_code_filter.artifacts import junit_xml, markdown_report, sarif_dict
from ai_code_filter.models import Issue, Report, Severity


def golden_report() -> Report:
    report = Report()
    report.add(Issue(file="app.py", category="PY002: Security", severity=Severity.CRITICAL, detector="rule_catalog", description="Unsafe eval.", recommendation="Remove eval.", location="eval(x)", line_number=7))
    return report


def test_golden_markdown_contains_stable_core_fields():
    md = markdown_report(golden_report())
    assert "| TOTAL | 1 |" in md
    assert "### CRITICAL: PY002: Security" in md
    assert "- File: `app.py`" in md
    assert "eval(x)" in md


def test_golden_sarif_contains_stable_core_fields():
    sarif = sarif_dict(golden_report())
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "PY002"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7


def test_golden_junit_contains_stable_core_fields():
    root = ET.fromstring(junit_xml(golden_report()))
    assert root.attrib["tests"] == "1"
    assert root.attrib["failures"] == "1"
    failure = root.find("testcase/failure")
    assert failure is not None
    assert failure.attrib["type"] == "CRITICAL"
