from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .evidence import EvidenceRecord, evidence_to_dict


SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _bucket_for(issue: dict[str, Any]) -> str:
    severity = str(issue.get("severity", "MEDIUM"))
    detector = str(issue.get("detector", ""))
    if severity == "CRITICAL":
        return "P0"
    if severity == "HIGH":
        return "P0" if detector in {"python_dataflow", "python_cross_file_dataflow", "unknown_call_validator"} else "P1"
    return "P2"


def _normalized_summary(report: dict[str, Any]) -> dict[str, int]:
    issues = list(report.get("issues", []))
    raw = dict(report.get("summary", {}) or {})
    computed = {severity: 0 for severity in SEVERITIES}
    for issue in issues:
        severity = str(issue.get("severity", "MEDIUM")).upper()
        if severity in computed:
            computed[severity] += 1
    computed["TOTAL"] = len(issues)
    computed["FAILED_FILES"] = len(report.get("failed_files", []) or [])
    computed["SKIPPED_FILES"] = len(report.get("skipped_files", []) or [])
    for key, value in raw.items():
        try:
            computed[key] = int(value)
        except (TypeError, ValueError):
            continue
    return computed


def maturity_score(summary: dict[str, int]) -> int:
    total = int(summary.get("TOTAL", 0))
    failed = int(summary.get("FAILED_FILES", 0))
    skipped = int(summary.get("SKIPPED_FILES", 0))
    critical = int(summary.get("CRITICAL", 0))
    high = int(summary.get("HIGH", 0))
    medium = int(summary.get("MEDIUM", 0))
    penalty = critical * 18 + high * 8 + medium * 3 + failed * 20 + skipped * 2
    if total == 0 and failed == 0:
        return max(0, 100 - skipped * 2)
    return max(0, min(100, 100 - penalty))


def build_review_plan(report: dict[str, Any]) -> dict[str, Any]:
    issues = list(report.get("issues", []))
    summary = _normalized_summary(report)
    buckets: dict[str, list[dict[str, Any]]] = {"P0": [], "P1": [], "P2": []}
    by_detector = Counter(str(issue.get("detector", "unknown")) for issue in issues)
    by_file: dict[str, int] = defaultdict(int)
    for issue in issues:
        by_file[str(issue.get("file", "<unknown>"))] += 1
        buckets[_bucket_for(issue)].append(issue)
    for key in buckets:
        buckets[key].sort(key=lambda item: (SEVERITY_RANK.get(str(item.get("severity", "MEDIUM")), 2), str(item.get("file", ""))))
    evidence = [
        EvidenceRecord("fact", f"Issues in report: {summary['TOTAL']}", "native report", "high"),
        EvidenceRecord("fact", f"Failed files: {summary['FAILED_FILES']}", "native report", "high"),
        EvidenceRecord("fact", f"Skipped files: {summary['SKIPPED_FILES']}", "native report", "high"),
    ]
    stop_condition = "No CRITICAL/HIGH issues, no failed files, accepted skipped-tool list, benchmark green."
    return {
        "maturity_score": maturity_score(summary),
        "stop_condition": stop_condition,
        "queues": {"P0": buckets["P0"][:25], "P1": buckets["P1"][:50], "P2": buckets["P2"][:50]},
        "counts": {
            "P0": len(buckets["P0"]),
            "P1": len(buckets["P1"]),
            "P2": len(buckets["P2"]),
            "by_detector": dict(sorted(by_detector.items())),
            "top_files": dict(sorted(by_file.items(), key=lambda item: (-item[1], item[0]))[:20]),
            "summary": summary,
        },
        "evidence": evidence_to_dict(evidence),
        "risks": _risks(report, buckets, summary),
        "verification_commands": [
            "python -m compileall -q ai_code_filter ai_filter.py",
            "python -m pytest -q",
            "python ai_filter.py analyze . --no-ai --no-drift --sdk-index --unknown-call-check",
            "python ai_filter.py benchmark --ci",
            "python ai_filter.py type-check .",
        ],
    }


def _risks(report: dict[str, Any], buckets: dict[str, list[dict[str, Any]]], summary: dict[str, int]) -> list[str]:
    risks: list[str] = []
    if buckets["P0"]:
        risks.append("P0 queue is not empty; release gate must fail until reviewed.")
    if summary.get("FAILED_FILES", 0):
        risks.append("Some files were not fully analyzed; report completeness is reduced.")
    if summary.get("SKIPPED_FILES", 0):
        risks.append("Some optional tools/files were skipped; verify whether skips are accepted.")
    if not risks:
        risks.append("No blocking risk found in the supplied report.")
    return risks
