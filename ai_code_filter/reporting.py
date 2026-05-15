from __future__ import annotations

import json
from pathlib import Path

from .models import Report


def print_report(report: Report, max_width: int = 140) -> None:
    """Display a human-readable report and return None."""
    summary = report.summary()
    if summary["TOTAL"] == 0:
        print("No problems found.")
        if summary["SKIPPED_FILES"]:
            print(f"Skipped files: {summary['SKIPPED_FILES']}")
        return
    print(
        f"Problems found: {summary['TOTAL']} | "
        f"CRITICAL={summary['CRITICAL']} HIGH={summary['HIGH']} "
        f"MEDIUM={summary['MEDIUM']} LOW={summary['LOW']} | "
        f"FAILED={summary['FAILED_FILES']} SKIPPED={summary['SKIPPED_FILES']}"
    )
    by_detector = report.by_detector()
    if by_detector:
        print("By detector: " + ", ".join(f"{name}={count}" for name, count in by_detector.items()))
    for issue in report.issues:
        print(f"  [{issue.severity.value}] {issue.file}")
        print(f"    Detector: {issue.detector} | Category: {issue.category}")
        if issue.line_number:
            print(f"    Line: {issue.line_number}")
        if issue.location:
            loc = issue.location.strip()
            print(f"    Code: {loc[:max_width]}{'...' if len(loc) > max_width else ''}")
        print(f"    Description: {issue.description[:max_width]}{'...' if len(issue.description) > max_width else ''}")
        print(f"    Recommendation: {issue.recommendation[:max_width]}{'...' if len(issue.recommendation) > max_width else ''}")
        print()


def write_json_report(report: Report, output: str | None) -> None:
    """Write a JSON report when output is provided; otherwise return None."""
    if not output:
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
