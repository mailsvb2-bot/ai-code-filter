from __future__ import annotations

import html
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Issue, Report, Severity
from .policy import issue_fingerprint


def _rule_id(issue: Issue) -> str:
    return issue.category.split(":", 1)[0] if ":" in issue.category else issue.category


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }[severity]


def _junit_classname(issue: Issue) -> str:
    return f"ai_code_filter.{issue.detector}.{_rule_id(issue)}".replace(" ", "_")


def _issue_result(issue: Issue) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _rule_id(issue),
        "level": _sarif_level(issue.severity),
        "message": {"text": issue.description},
        "partialFingerprints": {"aiCodeFilterFingerprint": issue_fingerprint(issue)},
        "properties": {"recommendation": issue.recommendation, "category": issue.category, "detector": issue.detector, "confidence": issue.confidence, "evidence": issue.evidence or {}},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": issue.file},
                "region": {"startLine": issue.line_number or 1},
            }
        }],
    }
    if issue.location:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": issue.location}
    return result


def sarif_dict(report: Report) -> dict[str, Any]:
    """Return a SARIF 2.1.0 payload for code-scanning integrations."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for issue in report.issues:
        rule_id = _rule_id(issue)
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": issue.category,
            "shortDescription": {"text": issue.category},
            "fullDescription": {"text": issue.recommendation or issue.description},
            "defaultConfiguration": {"level": _sarif_level(issue.severity)},
            "properties": {"severity": issue.severity.value, "detector": issue.detector, "confidence": issue.confidence},
        })
        results.append(_issue_result(issue))
    invocations = [{
        "executionSuccessful": not report.failed_files,
        "toolExecutionNotifications": [
            {"level": "error", "message": {"text": f"Failed to analyze {item['file']}: {item.get('error', '')}"}}
            for item in report.failed_files
        ] + [
            {"level": "note", "message": {"text": f"Skipped {item['file']}: {item.get('reason', '')}"}}
            for item in report.skipped_files
        ],
    }]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ai-code-filter",
                    "informationUri": "https://example.invalid/ai-code-filter",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": invocations,
            "properties": {"generatedAt": datetime.now(timezone.utc).isoformat(), "summary": report.summary()},
        }],
    }


def junit_xml(report: Report) -> str:
    """Return JUnit XML where issues are failures and incomplete inputs are explicit cases."""
    summary = report.summary()
    total_cases = max(1, summary["TOTAL"] + summary["FAILED_FILES"] + summary["SKIPPED_FILES"])
    suite = ET.Element(
        "testsuite",
        {
            "name": "ai-code-filter",
            "tests": str(total_cases),
            "failures": str(summary["TOTAL"]),
            "errors": str(summary["FAILED_FILES"]),
            "skipped": str(summary["SKIPPED_FILES"]),
        },
    )
    if not report.issues and not report.failed_files and not report.skipped_files:
        ET.SubElement(suite, "testcase", {"classname": "ai_code_filter", "name": "no_blocking_issues"})
    for issue in report.issues:
        case = ET.SubElement(suite, "testcase", {"classname": _junit_classname(issue), "name": f"{issue.file}:{issue.line_number or 1}"})
        failure = ET.SubElement(case, "failure", {"type": issue.severity.value, "message": issue.description})
        failure.text = f"{issue.category}\n{issue.file}:{issue.line_number or 1}\n{issue.location or ''}\nRecommendation: {issue.recommendation}"
    for item in report.failed_files:
        case = ET.SubElement(suite, "testcase", {"classname": "ai_code_filter.failed_file", "name": item.get("file", "<unknown>")})
        error = ET.SubElement(case, "error", {"type": "AnalyzerFailure", "message": item.get("error", "analysis failed")})
        error.text = item.get("error", "analysis failed")
    for item in report.skipped_files:
        case = ET.SubElement(suite, "testcase", {"classname": "ai_code_filter.skipped_file", "name": item.get("file", "<unknown>")})
        skipped = ET.SubElement(case, "skipped", {"message": item.get("reason", "skipped")})
        skipped.text = item.get("reason", "skipped")
    return ET.tostring(suite, encoding="unicode")


def markdown_report(report: Report) -> str:
    summary = report.summary()
    lines = [
        "# AI Code Filter Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    for key in ("TOTAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "FAILED_FILES", "SKIPPED_FILES"):
        lines.append(f"| {key} | {summary[key]} |")
    lines.extend(["", "## Issues", ""])
    if not report.issues:
        lines.append("No problems found.")
    for issue in report.issues:
        lines.extend([
            f"### {issue.severity.value}: {issue.category}",
            "",
            f"- File: `{issue.file}`",
            f"- Line: `{issue.line_number or ''}`",
            f"- Detector: `{issue.detector}`",
            f"- Description: {issue.description}",
            f"- Recommendation: {issue.recommendation}",
        ])
        if issue.location:
            lines.extend(["", "```", issue.location, "```"])
        lines.append("")
    if report.failed_files:
        lines.extend(["", "## Failed files", ""])
        for item in report.failed_files:
            lines.append(f"- `{item.get('file', '<unknown>')}` — {item.get('error', '')}")
    if report.skipped_files:
        lines.extend(["", "## Skipped files", ""])
        for item in report.skipped_files:
            lines.append(f"- `{item.get('file', '<unknown>')}` — {item.get('reason', '')}")
    return "\n".join(lines)


def html_report(report: Report) -> str:
    md = markdown_report(report)
    escaped = html.escape(md)
    return "\n".join([
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head><meta charset=\"utf-8\"><title>AI Code Filter Report</title>",
        "<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:32px;max-width:1100px;line-height:1.45}pre{background:#f6f8fa;padding:16px;border-radius:8px;overflow:auto}code{background:#f6f8fa;padding:2px 4px;border-radius:4px}</style>",
        "</head><body><pre>",
        escaped,
        "</pre></body></html>",
    ])


def _write_text(output: str | None, content: str) -> None:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def write_sarif_report(report: Report, output: str | None) -> None:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sarif_dict(report), ensure_ascii=False, indent=2), encoding="utf-8")


def write_junit_report(report: Report, output: str | None) -> None:
    _write_text(output, junit_xml(report))


def write_markdown_report(report: Report, output: str | None) -> None:
    _write_text(output, markdown_report(report))


def write_html_report(report: Report, output: str | None) -> None:
    _write_text(output, html_report(report))
