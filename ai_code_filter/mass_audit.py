from __future__ import annotations

import ast
from pathlib import Path

from .models import Issue, Report, Severity

_DEFAULT_LIMITS = {
    "max_python_files": 220,
    "max_module_lines": 900,
    "max_cli_subcommands": 80,
    "max_suite_modules_without_registry": 0,
}


def _python_files(root: Path) -> list[Path]:
    ignored = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "dist", "build"}
    return [p for p in root.rglob("*.py") if not any(part in ignored for part in p.parts)]


def mass_audit_summary(project: str | Path) -> dict:
    root = Path(project).resolve()
    files = _python_files(root) if root.exists() else []
    largest = []
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8").count("\n") + 1
        except Exception:
            lines = -1
        largest.append({"path": str(path.relative_to(root)) if path.is_relative_to(root) else str(path), "lines": lines})
    largest.sort(key=lambda item: item["lines"], reverse=True)
    suite_modules = [item for item in largest if item["path"].startswith("ai_code_filter/") and item["path"].endswith(".py") and ("suite" in item["path"] or item["path"].split("/")[-1] in {"adversarial.py", "blindspots.py"})]
    return {
        "schema_version": "1.0",
        "project_root": str(root),
        "python_file_count": len(files),
        "largest_modules": largest[:20],
        "suite_module_count": len(suite_modules),
        "limits": dict(_DEFAULT_LIMITS),
    }


def run_mass_audit(project: str | Path, *, strict: bool = False) -> Report:
    root = Path(project).resolve()
    report = Report()
    if not root.exists() or not root.is_dir():
        report.add(Issue(str(project), "Architecture mass", Severity.HIGH, "mass_audit", "Project root does not exist or is not a directory.", "Pass a real project directory."))
        return report
    summary = mass_audit_summary(root)
    if summary["python_file_count"] > _DEFAULT_LIMITS["max_python_files"]:
        report.add(Issue(str(root), "Architecture mass", Severity.MEDIUM, "mass_audit", f"Python file count is high: {summary['python_file_count']}", "Review module boundaries and remove stale wrappers before adding new suites."))
    for item in summary["largest_modules"]:
        if int(item["lines"]) > _DEFAULT_LIMITS["max_module_lines"]:
            report.add(Issue(item["path"], "Architecture mass", Severity.MEDIUM, "mass_audit", f"Large module: {item['lines']} lines.", "Split the module or move ownership to a focused component."))
    if strict:
        registry_path = root / "ai_code_filter" / "capabilities" / "registry.py"
        if not registry_path.exists():
            report.add(Issue("ai_code_filter/capabilities/registry.py", "Architecture mass", Severity.HIGH, "mass_audit", "Capability registry is missing.", "Add a unified capability registry before adding more suite modules."))
    return report
