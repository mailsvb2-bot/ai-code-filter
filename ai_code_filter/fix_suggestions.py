from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_fix_suggestions(report_data: dict[str, Any]) -> dict[str, Any]:
    """Build safe, review-only remediation suggestions from a native report.

    The function never edits files. It emits deterministic suggestions only when the
    category/evidence is specific enough to avoid pretending an unsafe auto-fix is safe.
    """
    suggestions: list[dict[str, Any]] = []
    for issue in report_data.get("issues", []):
        if not isinstance(issue, dict):
            continue
        category = str(issue.get("category", ""))
        evidence = issue.get("evidence") if isinstance(issue.get("evidence"), dict) else {}
        callsite = evidence.get("callsite") or issue.get("location")
        base = {
            "file": issue.get("file"),
            "line": issue.get("line_number"),
            "category": category,
            "confidence": issue.get("confidence", "medium"),
            "mode": "review_only",
        }
        if category.startswith("PY008") and isinstance(callsite, str) and "timeout" not in callsite:
            suggestions.append(base | {
                "kind": "add_timeout",
                "summary": "Add an explicit timeout to the HTTP request.",
                "suggested_change": "Add timeout=<bounded seconds> and handle timeout exceptions; review service-level latency before choosing the value.",
                "safe_to_apply_automatically": False,
                "reason": "Timeout value is domain-dependent, so the tool only suggests a review patch.",
            })
        elif category.startswith("PY007"):
            suggestions.append(base | {
                "kind": "replace_yaml_load",
                "summary": "Replace unsafe yaml.load with yaml.safe_load or an explicit SafeLoader.",
                "suggested_change": "Use yaml.safe_load(data) unless object construction is intentionally required and reviewed.",
                "safe_to_apply_automatically": False,
                "reason": "Changing YAML loader semantics may affect object construction and must be reviewed.",
            })
        elif category.startswith("PYDF002") or category.startswith("PYXDF002"):
            suggestions.append(base | {
                "kind": "harden_shell_execution",
                "summary": "Remove shell=True / os.system style execution for tainted input.",
                "suggested_change": "Use argument-list execution with shell=False, an allow-list, timeout and explicit error handling.",
                "safe_to_apply_automatically": False,
                "reason": "Command construction is semantic and cannot be safely rewritten generically.",
            })
    return {"schema_version": 1, "suggestions": suggestions, "count": len(suggestions)}


def build_fix_suggestions_from_file(path: str | Path) -> dict[str, Any]:
    """Load a native report and return review-only suggestions.

    Raises:
        json.JSONDecodeError: when the report is not valid JSON.
        ValueError: when the JSON root is not an object.
        OSError: when the file cannot be read.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("native report must be a JSON object")
    return build_fix_suggestions(data)
