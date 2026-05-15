from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import Issue, Report, Severity
from .type_resolution.dependencies import DependencyResolver
import tomllib

_VERSION_PIN_RE = re.compile(r"[<>=!~]=|===")


def _collect_local_import_roots(root: Path) -> set[str]:
    ignored = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "dist", "build"}
    roots: set[str] = set()
    for path in root.rglob("*.py"):
        if any(part in ignored for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    roots.add(alias.name.split(".", 1)[0])
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                roots.add(node.module.split(".", 1)[0])
    return roots


def dependency_audit_summary(project: str | Path) -> dict:
    root = Path(project).resolve()
    manifest = DependencyResolver(root).resolve()
    imports = sorted(_collect_local_import_roots(root)) if root.exists() else []
    return {
        "schema_version": "1.0",
        "project_root": str(root),
        "python_dependencies": manifest.python_dependencies,
        "python_import_roots": manifest.python_import_roots,
        "javascript_dependencies": manifest.javascript_dependencies,
        "lockfiles": manifest.lockfiles,
        "sources": manifest.sources,
        "local_python_import_roots": imports,
    }


def run_dependency_audit(project: str | Path) -> Report:
    root = Path(project).resolve()
    report = Report()
    if not root.exists() or not root.is_dir():
        report.add(Issue(str(project), "Dependency audit", Severity.HIGH, "dependency_audit", "Project root does not exist or is not a directory.", "Pass a real project directory."))
        return report
    summary = dependency_audit_summary(root)
    deps = list(summary["python_dependencies"])
    lower_seen: dict[str, str] = {}
    for dep in deps:
        name = re.split(r"[<>=!~;\[]", dep, maxsplit=1)[0].strip().lower().replace("_", "-")
        if not name:
            continue
        if name in lower_seen and lower_seen[name] != dep:
            report.add(Issue("pyproject.toml/requirements", "Dependency audit", Severity.HIGH, "dependency_audit", f"Duplicate/conflicting dependency declaration for {name}: {lower_seen[name]!r} and {dep!r}.", "Keep one canonical dependency constraint per package."))
        lower_seen[name] = dep
        if not _VERSION_PIN_RE.search(dep) and name not in {"openai"}:  # openai is optional in this project; direct deps may be empty.
            report.add(Issue("pyproject.toml/requirements", "Dependency audit", Severity.LOW, "dependency_audit", f"Dependency is unpinned or unconstrained: {dep}", "Pin or constrain production dependencies deliberately."))
    pyproject = root / "pyproject.toml"
    mandatory_deps = []
    if pyproject.exists():
        try:
            mandatory_deps = (tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {}) or {}).get("dependencies", []) or []
        except Exception:
            mandatory_deps = []
    mandatory_roots = [re.split(r"[<>=!~;\[]", str(dep), maxsplit=1)[0].strip().lower().replace("_", "-") for dep in mandatory_deps]
    if "openai" in mandatory_roots:
        report.add(Issue("pyproject.toml", "Dependency audit", Severity.HIGH, "dependency_audit", "OpenAI appears as a mandatory dependency.", "Keep OpenAI in optional extras because AI review is optional."))
    return report
