from __future__ import annotations

from typing import Any

from .review_plan import build_review_plan

PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2}


def _action_for(issue: dict[str, Any]) -> str:
    category = str(issue.get("category", ""))
    detector = str(issue.get("detector", ""))
    recommendation = str(issue.get("recommendation", "")).strip()
    if recommendation:
        return recommendation
    if "secret" in category.lower():
        return "Move secret material to environment or a secret manager and rotate exposed values."
    if "dataflow" in detector:
        return "Add validation, sanitization, and safe sink APIs before passing external input."
    if "unknown" in detector:
        return "Verify dependency version, import path, and method existence with type tools or SDK docs."
    return "Review the flagged code path and add a focused regression test before changing behavior."


def _failed_items(report: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for failure in report.get("failed_files", []) or []:
        items.append({
            "priority": "P0",
            "file": failure.get("file", "<unknown>"),
            "line_number": None,
            "severity": "HIGH",
            "detector": "pipeline",
            "category": "Analyzer failure",
            "action": f"Fix analyzer failure or explicitly exclude the file: {failure.get('error', '')}",
            "validation": ["Re-run the same analyze command and confirm FAILED_FILES=0."],
        })
    return items


def _skipped_items(report: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for skipped in report.get("skipped_files", []) or []:
        items.append({
            "priority": "P2",
            "file": skipped.get("file", "<unknown>"),
            "line_number": None,
            "severity": "LOW",
            "detector": "pipeline",
            "category": "Skipped input/tool",
            "action": f"Decide whether this skip is acceptable and document the decision: {skipped.get('reason', '')}",
            "validation": ["Re-run with the optional tool installed or record accepted skip governance."],
        })
    return items


def build_patch_plan(report: dict[str, Any], max_items: int = 40) -> dict[str, Any]:
    review = build_review_plan(report)
    items: list[dict[str, Any]] = []
    items.extend(_failed_items(report))
    for bucket in ("P0", "P1", "P2"):
        for issue in review["queues"][bucket]:
            items.append({
                "priority": bucket,
                "file": issue.get("file"),
                "line_number": issue.get("line_number"),
                "severity": issue.get("severity"),
                "detector": issue.get("detector"),
                "category": issue.get("category"),
                "action": _action_for(issue),
                "validation": [
                    "Add or update a regression test that fails before the patch.",
                    "Run the narrow test first, then run python -m pytest -q.",
                    "Run ai_filter.py analyze on the touched path with --no-ai --no-drift.",
                ],
            })
    items.extend(_skipped_items(report))
    items.sort(key=lambda item: (PRIORITY_RANK.get(str(item.get("priority", "P2")), 2), str(item.get("file", ""))))
    return {"items": items[:max_items], "truncated": len(items) > max_items, "source_maturity_score": review["maturity_score"]}
