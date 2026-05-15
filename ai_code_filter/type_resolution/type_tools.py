from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..models import Issue, Severity


@dataclass(frozen=True)
class TypeToolResult:
    tool: str
    available: bool
    returncode: int | None
    issues: tuple[Issue, ...]
    raw_summary: str = ""


class TypeToolAdapter:
    """Optional bridge to external type checkers. It never installs tools itself."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()

    def run_pyright(self) -> TypeToolResult:
        if not self.project_root.exists():
            return TypeToolResult("pyright", False, None, (), f"project root does not exist: {self.project_root}")
        executable = shutil.which("pyright")
        if not executable:
            return TypeToolResult("pyright", False, None, (), "pyright executable not found")
        try:
            proc = subprocess.run([executable, "--outputjson", str(self.project_root)], cwd=self.project_root, text=True, capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            return TypeToolResult("pyright", True, None, (Issue(file="<pyright>", category="Type checker timeout", severity=Severity.HIGH, detector="pyright", description="Pyright timed out after 120 seconds.", recommendation="Narrow the checked path or fix pyright configuration/performance."),), "timeout")
        except OSError as exc:
            return TypeToolResult("pyright", False, None, (), f"{type(exc).__name__}: {exc}")
        issues = self._parse_pyright(proc.stdout)
        return TypeToolResult("pyright", True, proc.returncode, tuple(issues), proc.stderr.strip())

    def run_mypy(self) -> TypeToolResult:
        if not self.project_root.exists():
            return TypeToolResult("mypy", False, None, (), f"project root does not exist: {self.project_root}")
        executable = shutil.which("mypy")
        if not executable:
            return TypeToolResult("mypy", False, None, (), "mypy executable not found")
        try:
            proc = subprocess.run([executable, "--show-error-codes", "--no-error-summary", str(self.project_root)], cwd=self.project_root, text=True, capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            return TypeToolResult("mypy", True, None, (Issue(file="<mypy>", category="Type checker timeout", severity=Severity.HIGH, detector="mypy", description="Mypy timed out after 120 seconds.", recommendation="Narrow the checked path or fix mypy configuration/performance."),), "timeout")
        except OSError as exc:
            return TypeToolResult("mypy", False, None, (), f"{type(exc).__name__}: {exc}")
        issues = self._parse_mypy(proc.stdout)
        return TypeToolResult("mypy", True, proc.returncode, tuple(issues), proc.stderr.strip())

    def _parse_pyright(self, stdout: str) -> list[Issue]:
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return [Issue(file=str(self.project_root), category="Type checker output", severity=Severity.LOW, detector="pyright", description="Pyright returned non-JSON output.", recommendation="Run pyright manually and inspect stdout.")]
        issues: list[Issue] = []
        for diag in data.get("generalDiagnostics", []) or []:
            severity = Severity.HIGH if diag.get("severity") == "error" else Severity.MEDIUM
            file = diag.get("file", "<pyright>")
            try:
                file = str(Path(file).resolve().relative_to(self.project_root))
            except (OSError, ValueError):
                file = str(file)
            rng = diag.get("range", {}) or {}
            start = rng.get("start", {}) or {}
            issues.append(Issue(file=file, category="Type checker", severity=severity, detector="pyright", description=diag.get("message", "Pyright diagnostic"), recommendation="Fix the type/import/attribute issue reported by pyright.", line_number=(start.get("line", 0) + 1 if isinstance(start.get("line"), int) else None)))
        return issues

    def _parse_mypy(self, stdout: str) -> list[Issue]:
        issues: list[Issue] = []
        for line in stdout.splitlines():
            if not line.strip() or ": error:" not in line:
                continue
            parts = line.split(":", 2)
            file = parts[0]
            line_no = None
            if len(parts) > 1 and parts[1].isdigit():
                line_no = int(parts[1])
            issues.append(Issue(file=file, category="Type checker", severity=Severity.HIGH, detector="mypy", description=line, recommendation="Fix the type/import/attribute issue reported by mypy.", line_number=line_no))
        return issues
