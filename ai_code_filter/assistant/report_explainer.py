from __future__ import annotations

import json
from typing import Any

from .patch_plan import build_patch_plan
from .review_plan import build_review_plan


def explain_report(report: dict[str, Any], *, as_markdown: bool = True) -> str | dict[str, Any]:
    review = build_review_plan(report)
    patch = build_patch_plan(report, max_items=15)
    data = {"review_plan": review, "patch_plan": patch}
    if not as_markdown:
        return data
    return _markdown(data)


def _markdown(data: dict[str, Any]) -> str:
    review = data["review_plan"]
    patch = data["patch_plan"]
    lines = [
        "# AI Code Filter assistant review",
        "",
        f"Maturity score: **{review['maturity_score']}/100**",
        "",
        "## Queues",
        f"- P0: {review['counts']['P0']}",
        f"- P1: {review['counts']['P1']}",
        f"- P2: {review['counts']['P2']}",
        "",
        "## Stop condition",
        review["stop_condition"],
        "",
        "## Risks",
    ]
    for risk in review["risks"]:
        lines.append(f"- {risk}")
    lines.extend(["", "## Patch queue"])
    if not patch["items"]:
        lines.append("No patch items generated from the supplied report.")
    for item in patch["items"]:
        line = item.get("line_number")
        where = f":{line}" if line else ""
        lines.append(f"- **{item['priority']}** {item['file']}{where} — {item['action']}")
    lines.extend(["", "## Verification", *[f"- `{cmd}`" for cmd in review["verification_commands"]]])
    lines.extend(["", "## Raw counts", "```json", json.dumps(review["counts"], ensure_ascii=False, indent=2), "```"])
    return "\n".join(lines) + "\n"
