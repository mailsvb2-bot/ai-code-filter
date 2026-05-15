from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class CoverageAuditSummary:
    tool_available: bool
    pytest_returncode: int | None
    line_percent: float | None
    branch_percent: float | None
    measured_files: int
    raw: dict[str, Any]
    top_uncovered_files: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_available": self.tool_available,
            "pytest_returncode": self.pytest_returncode,
            "line_percent": self.line_percent,
            "branch_percent": self.branch_percent,
            "measured_files": self.measured_files,
            "raw": self.raw,
            "top_uncovered_files": list(self.top_uncovered_files),
        }


def audit_coverage(
    project: str | Path,
    *,
    min_lines: float = 0.0,
    min_branches: float | None = None,
    max_uncovered_files: int | None = None,
    timeout: int = 1800,
    pytest_args: tuple[str, ...] = (),
    disable_plugin_autoload: bool = True,
) -> tuple[Report, CoverageAuditSummary]:
    """Run coverage.py over pytest and convert coverage budgets into FindingCore issues.

    This is an execution gate, not a proof of semantic correctness. It answers:
    "did the test suite actually execute production lines/branches above a reviewable threshold?"
    """
    root = Path(project).resolve()
    report = Report()
    with tempfile.TemporaryDirectory(prefix="aicf_cov_") as tmp:
        json_path = Path(tmp) / "coverage.json"
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if disable_plugin_autoload:
            env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(root) if not existing else f"{root}{os.pathsep}{existing}"
        cmd = [sys.executable, "-m", "coverage", "run", "--branch", "-m", "pytest", *pytest_args]
        try:
            proc = subprocess.run(cmd, cwd=str(root), env=env, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            report.add(Issue(
                file=str(root),
                category="COV002: coverage pytest timeout",
                severity=Severity.CRITICAL,
                detector="coverage_audit",
                description=f"coverage.py pytest run timed out after {timeout} seconds.",
                recommendation="Fix hanging tests or lower the checked scope before treating coverage as a release gate.",
                confidence="high",
                evidence={"timeout": timeout, "stdout_tail": _tail(_as_text(exc.stdout)), "stderr_tail": _tail(_as_text(exc.stderr))},
            ))
            return FindingCore().process(report).report, CoverageAuditSummary(True, None, None, None, 0, {})
        if "No module named coverage" in (proc.stderr or ""):
            report.add(Issue(
                file=str(root),
                category="COV001: coverage tool unavailable",
                severity=Severity.HIGH,
                detector="coverage_audit",
                description="coverage.py is not installed in this environment.",
                recommendation="Install coverage.py or disable coverage-audit explicitly; do not claim branch/line coverage without the tool.",
                confidence="high",
                evidence={"stderr_tail": _tail(proc.stderr)},
            ))
            return FindingCore().process(report).report, CoverageAuditSummary(False, proc.returncode, None, None, 0, {})
        if proc.returncode != 0:
            report.add(Issue(
                file=str(root),
                category="COV002: coverage pytest failed",
                severity=Severity.CRITICAL,
                detector="coverage_audit",
                description="pytest failed while running under coverage.py, so coverage metrics are not release-grade.",
                recommendation="Fix the failing tests before using coverage numbers as a quality gate.",
                confidence="high",
                evidence={"returncode": proc.returncode, "stdout_tail": _tail(proc.stdout), "stderr_tail": _tail(proc.stderr)},
            ))
        json_proc = subprocess.run([sys.executable, "-m", "coverage", "json", "-o", str(json_path)], cwd=str(root), env=env, text=True, capture_output=True, timeout=120)
        if json_proc.returncode != 0 or not json_path.exists():
            report.add(Issue(
                file=str(root),
                category="COV006: coverage json unavailable",
                severity=Severity.HIGH,
                detector="coverage_audit",
                description="coverage.py did not produce a JSON report.",
                recommendation="Run coverage json manually and fix coverage configuration/output errors.",
                confidence="high",
                evidence={"returncode": json_proc.returncode, "stdout_tail": _tail(json_proc.stdout), "stderr_tail": _tail(json_proc.stderr)},
            ))
            return FindingCore().process(report).report, CoverageAuditSummary(True, proc.returncode, None, None, 0, {})
        data = json.loads(json_path.read_text(encoding="utf-8"))
    totals = data.get("totals", {}) if isinstance(data, dict) else {}
    line_percent = _float(totals.get("percent_covered"))
    branch_percent = _branch_percent(totals)
    measured_files = len(data.get("files", {}) or {}) if isinstance(data, dict) else 0
    top_uncovered_files = _top_uncovered_files(data)
    if line_percent is not None and line_percent < min_lines:
        report.add(Issue(
            file=str(root),
            category="COV003: line coverage below budget",
            severity=Severity.HIGH,
            detector="coverage_audit",
            description=f"Line coverage is {line_percent:.2f}%, below required {min_lines:.2f}%.",
            recommendation="Add meaningful tests for uncovered production code or lower the budget with an explicit reviewed reason.",
            confidence="high",
            evidence={"line_percent": line_percent, "min_lines": min_lines, "measured_files": measured_files},
        ))
    if min_branches is not None and branch_percent is not None and branch_percent < min_branches:
        report.add(Issue(
            file=str(root),
            category="COV004: branch coverage below budget",
            severity=Severity.HIGH,
            detector="coverage_audit",
            description=f"Branch coverage is {branch_percent:.2f}%, below required {min_branches:.2f}%.",
            recommendation="Add tests for branch/error paths or lower the budget with an explicit reviewed reason.",
            confidence="high",
            evidence={"branch_percent": branch_percent, "min_branches": min_branches, "measured_files": measured_files},
        ))
    if max_uncovered_files is not None:
        uncovered_count = sum(1 for item in top_uncovered_files if int(item.get("missing_lines", 0)) > 0)
        if uncovered_count > max_uncovered_files:
            report.add(Issue(
                file=str(root),
                category="COV007: uncovered file budget exceeded",
                severity=Severity.HIGH,
                detector="coverage_audit",
                description=f"{uncovered_count} measured files have uncovered lines; budget is {max_uncovered_files}.",
                recommendation="Add tests for uncovered production files or adjust the budget with review.",
                confidence="medium",
                evidence={"top_uncovered_files": top_uncovered_files[:10], "max_uncovered_files": max_uncovered_files},
            ))
    if measured_files == 0:
        report.add(Issue(
            file=str(root),
            category="COV005: no files measured",
            severity=Severity.HIGH,
            detector="coverage_audit",
            description="coverage.py ran but measured zero source files.",
            recommendation="Fix coverage source configuration; zero measured files is usually an illusion of coverage.",
            confidence="high",
            evidence={"totals": totals},
        ))
    return FindingCore().process(report).report, CoverageAuditSummary(True, proc.returncode, line_percent, branch_percent, measured_files, {"totals": totals}, tuple(top_uncovered_files[:20]))


def write_coverage_summary(path: str | Path | None, summary: CoverageAuditSummary, report: Report) -> None:
    """Write summary JSON when a path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"coverage": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _branch_percent(totals: dict[str, Any]) -> float | None:
    covered = _float(totals.get("covered_branches"))
    missing = _float(totals.get("missing_branches"))
    if covered is None or missing is None:
        return None
    denom = covered + missing
    if denom <= 0:
        return None
    return round((covered / denom) * 100.0, 2)


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _tail(text: str, max_chars: int = 5000) -> str:
    return text[-max_chars:] if len(text) > max_chars else text


def _top_uncovered_files(data: dict[str, Any]) -> list[dict[str, Any]]:
    files = data.get("files", {}) if isinstance(data, dict) else {}
    out: list[dict[str, Any]] = []
    if not isinstance(files, dict):
        return out
    for name, info in files.items():
        if not isinstance(info, dict):
            continue
        missing = info.get("missing_lines") or []
        summary = info.get("summary") or {}
        out.append({
            "file": name,
            "missing_lines": len(missing) if isinstance(missing, list) else 0,
            "percent_covered": summary.get("percent_covered"),
        })
    return sorted(out, key=lambda item: (int(item.get("missing_lines") or 0), -(float(item.get("percent_covered") or 0.0))), reverse=True)
