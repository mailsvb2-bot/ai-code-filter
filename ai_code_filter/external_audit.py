from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .finding_core import FindingCore
from .models import Issue, Report, Severity
from .external_normalization import normalize_external_findings


@dataclass(frozen=True)
class ExternalToolResult:
    tool: str
    available: bool
    returncode: int | None
    stdout_tail: str = ""
    stderr_tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "available": self.available, "returncode": self.returncode, "stdout_tail": self.stdout_tail, "stderr_tail": self.stderr_tail}


@dataclass(frozen=True)
class ExternalAuditSummary:
    tools: tuple[ExternalToolResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"tools": [tool.to_dict() for tool in self.tools]}


def audit_external_tools(
    project: str | Path,
    *,
    tools: Iterable[str] = ("ruff", "bandit", "semgrep", "pip-audit"),
    timeout: int = 300,
    require_tools: bool = False,
) -> tuple[Report, ExternalAuditSummary]:
    root = Path(project).resolve()
    report = Report()
    results: list[ExternalToolResult] = []
    for tool in tools:
        tool = str(tool).strip().lower()
        result = _run_tool(root, tool, timeout=timeout)
        results.append(result)
        if not result.available:
            if require_tools:
                report.add(Issue(
                    file=str(root),
                    category="EXT001: external analyzer unavailable",
                    severity=Severity.HIGH,
                    detector="external_audit",
                    description=f"External analyzer {tool!r} is not available.",
                    recommendation="Install the analyzer or run without --require-tools; do not claim this external gate ran.",
                    confidence="high",
                    evidence=result.to_dict(),
                ))
            else:
                report.record_skip(f"<{tool}>", f"{tool} not available")
            continue
        normalized_tool = "pyright" if tool == "pyright" else tool
        if tool in {"ruff", "bandit", "semgrep"} and result.stdout_tail.strip():
            normalized, _summary = normalize_external_findings(normalized_tool, result.stdout_tail)
            if normalized.issues:
                report.extend(normalized.issues)
                continue
        if (result.returncode or 0) != 0:
            severity = Severity.HIGH if tool in {"bandit", "semgrep", "pip-audit"} else Severity.MEDIUM
            report.add(Issue(
                file=str(root),
                category="EXT010: external analyzer reported findings or failed",
                severity=severity,
                detector="external_audit",
                description=f"External analyzer {tool!r} exited non-zero.",
                recommendation="Inspect the external analyzer output and fix or baseline findings with rationale.",
                confidence="medium",
                evidence=result.to_dict(),
            ))
    return FindingCore().process(report).report, ExternalAuditSummary(tuple(results))


def write_external_audit_summary(path: str | Path | None, summary: ExternalAuditSummary, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"external_audit": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _run_tool(root: Path, tool: str, *, timeout: int) -> ExternalToolResult:
    cmd: list[str] | None = None
    if tool == "ruff":
        exe = shutil.which("ruff")
        if exe:
            cmd = [exe, "check", ".", "--output-format", "json"]
    elif tool == "bandit":
        exe = shutil.which("bandit")
        if exe:
            cmd = [exe, "-r", ".", "-q", "-f", "json"]
    elif tool == "semgrep":
        exe = shutil.which("semgrep")
        if exe:
            cmd = [exe, "scan", "--config", "auto", "--quiet", "--json", "."]
    elif tool in {"pip-audit", "pipaudit"}:
        exe = shutil.which("pip-audit")
        if exe:
            cmd = [exe, "-r", "requirements.txt"] if (root / "requirements.txt").exists() else [exe]
    else:
        return ExternalToolResult(tool, False, None)
    if not cmd:
        return ExternalToolResult(tool, False, None)
    env = os.environ.copy()
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    try:
        proc = subprocess.run(cmd, cwd=str(root), env=env, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return ExternalToolResult(tool, True, None, _tail(_as_text(exc.stdout)), _tail(_as_text(exc.stderr)))
    return ExternalToolResult(tool, True, proc.returncode, _tail(proc.stdout), _tail(proc.stderr))


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _tail(text: str, *, max_chars: int = 5000) -> str:
    return text[-max_chars:] if len(text) > max_chars else text
