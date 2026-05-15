from __future__ import annotations

import json
import os
import re
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
class TypeAuditToolResult:
    tool: str
    available: bool
    returncode: int | None
    stdout_tail: str = ""
    stderr_tail: str = ""
    issues_detected: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "available": self.available,
            "returncode": self.returncode,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "issues_detected": self.issues_detected,
        }


@dataclass(frozen=True)
class TypeAuditSummary:
    tools: tuple[TypeAuditToolResult, ...]
    untyped_public_functions: int
    type_ignore_without_reason: int
    any_leakage_signals: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": [item.to_dict() for item in self.tools],
            "untyped_public_functions": self.untyped_public_functions,
            "type_ignore_without_reason": self.type_ignore_without_reason,
            "any_leakage_signals": self.any_leakage_signals,
        }


def audit_type_intelligence(
    project: str | Path,
    *,
    engines: Iterable[str] = ("pyright", "mypy"),
    timeout: int = 300,
    require_tools: bool = False,
    max_untyped_public: int | None = None,
    fail_on_type_errors: bool = False,
) -> tuple[Report, TypeAuditSummary]:
    root = Path(project).resolve()
    report = Report()
    tool_results: list[TypeAuditToolResult] = []
    for engine in engines:
        engine = str(engine).strip().lower()
        if engine not in {"pyright", "mypy"}:
            report.add(Issue(
                file=str(root),
                category="TYPE001: unsupported type engine",
                severity=Severity.MEDIUM,
                detector="type_audit",
                description=f"Unsupported type audit engine: {engine!r}.",
                recommendation="Use pyright, mypy, or omit --engine to run both supported engines.",
                confidence="high",
                evidence={"engine": engine},
            ))
            continue
        result = _run_type_tool(root, engine, timeout=timeout)
        tool_results.append(result)
        if not result.available:
            if require_tools:
                report.add(Issue(
                    file=str(root),
                    category="TYPE010: type checker unavailable",
                    severity=Severity.HIGH,
                    detector="type_audit",
                    description=f"{engine} is not available, so type intelligence could not be verified.",
                    recommendation=f"Install {engine} or run without --require-tools; do not claim type-grade validation without a type checker.",
                    confidence="high",
                    evidence=result.to_dict(),
                ))
            else:
                report.record_skip(f"<{engine}>", f"{engine} executable/module not available")
            continue
        if fail_on_type_errors and (result.returncode or 0) != 0:
            if engine == "pyright" and result.stdout_tail.strip():
                normalized, _summary = normalize_external_findings("pyright", result.stdout_tail)
                if normalized.issues:
                    report.extend(normalized.issues)
                    continue
            report.add(Issue(
                file=str(root),
                category="TYPE020: type checker reported errors",
                severity=Severity.HIGH,
                detector="type_audit",
                description=f"{engine} reported type-checking errors.",
                recommendation="Fix type errors or explicitly baseline them with reviewed rationale.",
                confidence="high",
                evidence=result.to_dict(),
            ))
    static_issues, summary_counts = _audit_static_type_contract(root, max_untyped_public=max_untyped_public)
    report.extend(static_issues)
    summary = TypeAuditSummary(
        tools=tuple(tool_results),
        untyped_public_functions=summary_counts["untyped_public_functions"],
        type_ignore_without_reason=summary_counts["type_ignore_without_reason"],
        any_leakage_signals=summary_counts["any_leakage_signals"],
    )
    return FindingCore().process(report).report, summary


def write_type_audit_summary(path: str | Path | None, summary: TypeAuditSummary, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"type_audit": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _run_type_tool(root: Path, engine: str, *, timeout: int) -> TypeAuditToolResult:
    if engine == "pyright":
        exe = shutil.which("pyright")
        if exe:
            cmd = [exe, "--outputjson", "."]
        else:
            return TypeAuditToolResult(engine, False, None)
    else:
        exe = shutil.which("mypy")
        if exe:
            cmd = [exe, "--show-error-codes", "--no-error-summary", "."]
        else:
            return TypeAuditToolResult(engine, False, None)
    env = os.environ.copy()
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    try:
        proc = subprocess.run(cmd, cwd=str(root), env=env, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return TypeAuditToolResult(engine, True, None, _tail(_as_text(exc.stdout)), _tail(_as_text(exc.stderr)), 1)
    issues = _estimate_type_issues(engine, proc.stdout, proc.stderr)
    return TypeAuditToolResult(engine, True, proc.returncode, _tail(proc.stdout), _tail(proc.stderr), issues)


def _audit_static_type_contract(root: Path, *, max_untyped_public: int | None) -> tuple[list[Issue], dict[str, int]]:
    import ast

    issues: list[Issue] = []
    untyped = 0
    ignores = 0
    any_signals = 0
    for path in sorted(root.rglob("*.py")):
        if _is_ignored(path) or _is_test_path(path, root):
            continue
        rel = _rel(path, root)
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (SyntaxError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            ignore_marker = "type:" + " ignore"
            if ignore_marker in line and not re.search(r"(reason|because|#.*\[)", line, re.IGNORECASE):
                ignores += 1
                issues.append(Issue(
                    file=rel,
                    line_number=lineno,
                    category="TYPE031: type ignore lacks rationale",
                    severity=Severity.MEDIUM,
                    detector="type_audit",
                    description="A type ignore comment has no clear reviewed rationale.",
                    recommendation="Add a reason or remove the suppression by fixing the type error.",
                    confidence="medium",
                    evidence={"line": line.strip()},
                ))
            if re.search(r"\bAny\b|typing\.Any", line):
                any_signals += 1
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                args = list(node.args.args) + list(node.args.kwonlyargs)
                public_args = [a for a in args if a.arg not in {"self", "cls"}]
                missing_arg = any(a.annotation is None for a in public_args)
                missing_return = node.returns is None
                if missing_arg or missing_return:
                    untyped += 1
    if max_untyped_public is not None and untyped > max_untyped_public:
        issues.append(Issue(
            file=str(root),
            category="TYPE030: untyped public API budget exceeded",
            severity=Severity.HIGH,
            detector="type_audit",
            description=f"Found {untyped} public functions/methods with missing annotations; budget is {max_untyped_public}.",
            recommendation="Annotate public boundaries or lower the budget only with explicit review.",
            confidence="medium",
            evidence={"untyped_public_functions": untyped, "max_untyped_public": max_untyped_public},
        ))
    return issues, {"untyped_public_functions": untyped, "type_ignore_without_reason": ignores, "any_leakage_signals": any_signals}


def _estimate_type_issues(engine: str, stdout: str, stderr: str) -> int:
    text = f"{stdout}\n{stderr}"
    if engine == "pyright":
        try:
            data = json.loads(stdout)
            diagnostics = data.get("generalDiagnostics") if isinstance(data, dict) else None
            return len(diagnostics or [])
        except json.JSONDecodeError:
            return len(re.findall(r"\berror\b", text, re.IGNORECASE))
    return len([line for line in text.splitlines() if ": error:" in line])


def _is_test_path(path: Path, root: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        parts = path.parts
    return "tests" in parts or path.name.startswith("test_") or path.name.endswith("_test.py")


def _is_ignored(path: Path) -> bool:
    ignored = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}
    return any(part in ignored for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _tail(text: str, *, max_chars: int = 5000) -> str:
    return text[-max_chars:] if len(text) > max_chars else text
