from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Issue, Report, Severity

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "notice"}

def _load_report(path: str | Path) -> Report:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    report = Report()
    for row in data.get("issues", []) if isinstance(data, dict) else []:
        if not isinstance(row, dict):
            continue
        sev = Severity(row.get("severity", "MEDIUM")) if row.get("severity") in {s.value for s in Severity} else Severity.MEDIUM
        report.add(Issue(
            file=str(row.get("file", "<unknown>")),
            category=str(row.get("category", "unknown")),
            severity=sev,
            detector=str(row.get("detector", "unknown")),
            description=str(row.get("description", "")),
            recommendation=str(row.get("recommendation", "")),
            location=row.get("location"),
            line_number=row.get("line_number"),
            confidence=str(row.get("confidence", "medium")),
            evidence=row.get("evidence") if isinstance(row.get("evidence"), dict) else None,
        ))
    return report

@dataclass(frozen=True)
class GitHubAnnotationSummary:
    annotations: int
    errors: int
    warnings: int
    notices: int
    pr_comment_lines: int
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {"annotations": self.annotations, "errors": self.errors, "warnings": self.warnings, "notices": self.notices, "pr_comment_lines": self.pr_comment_lines, "truncated": self.truncated}

def _escape(value: str) -> str:
    return value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A').replace(',', '%2C').replace(':', '%3A')

def annotation_commands(report: Report, *, max_annotations: int = 50) -> tuple[list[str], GitHubAnnotationSummary]:
    commands: list[str] = []
    counts = {"error": 0, "warning": 0, "notice": 0}
    for issue in report.issues[:max_annotations]:
        level = _LEVEL.get(issue.severity, "warning")
        counts[level] += 1
        title = _escape(f"{issue.severity.value}: {issue.category}")
        msg = _escape(f"{issue.description} Recommendation: {issue.recommendation}".strip())
        commands.append(f"::{level} file={_escape(issue.file)},line={int(issue.line_number or 1)},title={title}::{msg}")
    return commands, GitHubAnnotationSummary(len(commands), counts["error"], counts["warning"], counts["notice"], 0, len(report.issues) > max_annotations)

def pr_comment_markdown(report: Report, *, max_items: int = 25) -> str:
    summary = report.summary()
    lines = ["## AI Code Filter review", "", f"**Total:** {summary['TOTAL']} · **Critical:** {summary['CRITICAL']} · **High:** {summary['HIGH']} · **Medium:** {summary['MEDIUM']} · **Low:** {summary['LOW']}", ""]
    if not report.issues:
        lines.append("No deterministic findings were reported.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Severity | File | Rule | Finding |", "|---|---|---|---|"])
    for issue in report.issues[:max_items]:
        desc = issue.description.replace("\n", " ")[:220]
        lines.append(f"| {issue.severity.value} | `{issue.file}:{issue.line_number or 1}` | `{issue.category}` | {desc} |")
    if len(report.issues) > max_items:
        lines.append(f"\n_Truncated: showing {max_items} of {len(report.issues)} findings. Upload SARIF for the full set._")
    return "\n".join(lines) + "\n"

def write_github_outputs(report_path: str | Path, *, annotations: str | Path | None = None, pr_comment: str | Path | None = None, summary_json: str | Path | None = None, max_annotations: int = 50) -> GitHubAnnotationSummary:
    report = _load_report(report_path)
    commands, base = annotation_commands(report, max_annotations=max_annotations)
    comment = pr_comment_markdown(report)
    summary = GitHubAnnotationSummary(base.annotations, base.errors, base.warnings, base.notices, len(comment.splitlines()), base.truncated)
    if annotations:
        Path(annotations).write_text("\n".join(commands) + ("\n" if commands else ""), encoding="utf-8")
    if pr_comment:
        Path(pr_comment).write_text(comment, encoding="utf-8")
    if summary_json:
        Path(summary_json).write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return summary
