from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .finding_core import FindingCore
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class NormalizationSummary:
    tool: str
    findings: int
    skipped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "findings": self.findings, "skipped": self.skipped}


def normalize_external_findings(tool: str, payload: str | bytes | dict[str, Any] | list[Any]) -> tuple[Report, NormalizationSummary]:
    """Normalize external analyzer JSON into native Issues.

    Supported JSON shapes: Ruff, Bandit, Semgrep and Pyright. This is an adapter,
    not a replacement for those tools. Unknown records are skipped rather than
    guessed into misleading findings.
    """
    tool = tool.strip().lower()
    data: Any
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        try:
            data = json.loads(payload or "null")
        except json.JSONDecodeError as exc:
            report = Report()
            report.add(Issue(file="<external>", category="EXTN001: invalid external JSON", severity=Severity.HIGH, detector="external_normalization", description=f"Could not parse {tool} JSON: {exc}", recommendation="Run the tool with JSON output enabled and provide the complete output.", confidence="high"))
            return report, NormalizationSummary(tool=tool, findings=1)
    else:
        data = payload
    if tool == "ruff":
        issues = _normalize_ruff(data)
    elif tool == "bandit":
        issues = _normalize_bandit(data)
    elif tool == "semgrep":
        issues = _normalize_semgrep(data)
    elif tool == "pyright":
        issues = _normalize_pyright(data)
    else:
        issues = [Issue(file="<external>", category="EXTN002: unsupported external tool", severity=Severity.MEDIUM, detector="external_normalization", description=f"Unsupported external tool: {tool}", recommendation="Use ruff, bandit, semgrep or pyright.", confidence="high")]
    report = Report()
    report.extend(issues)
    processed = FindingCore().process(report).report
    return processed, NormalizationSummary(tool=tool, findings=len(processed.issues))


def write_external_normalization_summary(path: str | Path | None, summary: NormalizationSummary, report: Report) -> None:
    """Write a summary JSON file; returns None when no path is supplied."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"external_normalization": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _sev(value: str | None, *, default: Severity = Severity.MEDIUM) -> Severity:
    v = (value or "").lower()
    if v in {"error", "critical", "high"}:
        return Severity.HIGH
    if v in {"warning", "medium"}:
        return Severity.MEDIUM
    if v in {"note", "information", "info", "low"}:
        return Severity.LOW
    return default


def _normalize_ruff(data: Any) -> list[Issue]:
    rows = data if isinstance(data, list) else []
    issues: list[Issue] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        loc = row.get("location") or {}
        code = str(row.get("code") or "ruff")
        issues.append(Issue(
            file=str(row.get("filename") or "<ruff>"),
            line_number=int(loc.get("row") or 1) if isinstance(loc, dict) else None,
            category=f"external.ruff.{code}",
            severity=Severity.MEDIUM,
            detector="external_normalization",
            description=str(row.get("message") or f"Ruff finding {code}"),
            recommendation="Review the Ruff finding and fix or baseline it with rationale.",
            confidence="high",
            evidence={"tool": "ruff", "code": code, "raw": row},
        ))
    return issues


def _normalize_bandit(data: Any) -> list[Issue]:
    rows = data.get("results", []) if isinstance(data, dict) else []
    issues: list[Issue] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        sev = _sev(str(row.get("issue_severity") or "medium"), default=Severity.MEDIUM)
        test_id = str(row.get("test_id") or "bandit")
        issues.append(Issue(
            file=str(row.get("filename") or "<bandit>"),
            line_number=int(row.get("line_number") or 1),
            category=f"external.bandit.{test_id}",
            severity=sev,
            detector="external_normalization",
            description=str(row.get("issue_text") or f"Bandit finding {test_id}"),
            recommendation="Review the Bandit security finding and fix or baseline it with rationale.",
            confidence=str(row.get("issue_confidence") or "medium").lower(),
            evidence={"tool": "bandit", "test_id": test_id, "raw": row},
        ))
    return issues


def _normalize_semgrep(data: Any) -> list[Issue]:
    rows = data.get("results", []) if isinstance(data, dict) else []
    issues: list[Issue] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        extra = row.get("extra") if isinstance(row.get("extra"), dict) else {}
        start = row.get("start") if isinstance(row.get("start"), dict) else {}
        rule_id = str(row.get("check_id") or "semgrep")
        issues.append(Issue(
            file=str(row.get("path") or "<semgrep>"),
            line_number=int(start.get("line") or 1),
            category=f"external.semgrep.{rule_id}",
            severity=_sev(str(extra.get("severity") or "medium")),
            detector="external_normalization",
            description=str(extra.get("message") or f"Semgrep finding {rule_id}"),
            recommendation="Review the Semgrep finding and fix or baseline it with rationale.",
            confidence="medium",
            evidence={"tool": "semgrep", "check_id": rule_id, "raw": row},
        ))
    return issues


def _normalize_pyright(data: Any) -> list[Issue]:
    rows = data.get("generalDiagnostics", []) if isinstance(data, dict) else []
    issues: list[Issue] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        rng = row.get("range") if isinstance(row.get("range"), dict) else {}
        start = rng.get("start") if isinstance(rng.get("start"), dict) else {}
        rule = str(row.get("rule") or row.get("severity") or "pyright")
        issues.append(Issue(
            file=str(row.get("file") or "<pyright>"),
            line_number=int(start.get("line", 0)) + 1 if isinstance(start, dict) else None,
            category=f"external.pyright.{rule}",
            severity=_sev(str(row.get("severity") or "error")),
            detector="external_normalization",
            description=str(row.get("message") or f"Pyright finding {rule}"),
            recommendation="Fix the type diagnostic or baseline it with reviewed rationale.",
            confidence="high",
            evidence={"tool": "pyright", "rule": rule, "raw": row},
        ))
    return issues
