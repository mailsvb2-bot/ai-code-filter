from __future__ import annotations

import json
import re
from pathlib import Path

from .finding_core import FindingCore
from .models import Issue, Report, Severity


def audit_supply_chain(project: str | Path) -> Report:
    root = Path(project).resolve()
    report = Report()
    for req in root.rglob("requirements*.txt"):
        if not _is_ignored(req):
            _audit_requirements(root, req, report)
    for pyproject in root.rglob("pyproject.toml"):
        if not _is_ignored(pyproject):
            _audit_pyproject(root, pyproject, report)
    for package in root.rglob("package.json"):
        if not _is_ignored(package):
            _audit_package_json(root, package, report)
    if not any((root / name).exists() for name in ("requirements.txt", "pyproject.toml", "package.json")):
        report.add(Issue(file=str(root), category="SUPPLY001: no dependency manifest found", severity=Severity.LOW, detector="supply_chain_audit", description="No common dependency manifest found at project root.", recommendation="Ensure dependencies are declared and reproducible if the project has runtime dependencies.", confidence="low"))
    return FindingCore().process(report).report


def write_supply_chain_summary(path: str | Path | None, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _audit_requirements(root: Path, path: Path, report: Report) -> None:
    for lineno, line in enumerate(_read(path).splitlines(), start=1):
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("-"):
            continue
        rel = _rel(path, root)
        if re.search(r"(git\+|https?://)", raw):
            report.add(Issue(file=rel, line_number=lineno, category="SUPPLY020: direct URL dependency", severity=Severity.HIGH, detector="supply_chain_audit", description="Dependency is installed from a direct URL/git source.", recommendation="Pin immutable hashes/commits and review source provenance.", confidence="medium", evidence={"line": raw}))
        if "==" not in raw and " @ " not in raw:
            report.add(Issue(file=rel, line_number=lineno, category="SUPPLY010: unpinned dependency", severity=Severity.MEDIUM, detector="supply_chain_audit", description="Requirement is not exactly pinned.", recommendation="Pin deploy dependencies exactly or use a lockfile.", confidence="medium", evidence={"line": raw}))
        if re.search(r"==\s*\*|>=\s*0", raw):
            report.add(Issue(file=rel, line_number=lineno, category="SUPPLY011: weak dependency version constraint", severity=Severity.MEDIUM, detector="supply_chain_audit", description="Requirement uses a weak/wildcard version constraint.", recommendation="Use reviewed exact pins or lockfiles for deployment.", confidence="medium", evidence={"line": raw}))


def _audit_pyproject(root: Path, path: Path, report: Report) -> None:
    text = _read(path)
    rel = _rel(path, root)
    dep_lines = [line.strip().strip('",') for line in text.splitlines() if re.match(r"\s*['\"][A-Za-z0-9_.-]+", line)]
    for line in dep_lines:
        if any(op in line for op in (">=", "<=", "~=", ">")) and "==" not in line:
            report.add(Issue(file=rel, category="SUPPLY012: broad pyproject dependency constraint", severity=Severity.LOW, detector="supply_chain_audit", description="pyproject dependency uses a broad version range.", recommendation="For deploy artifacts, pair pyproject ranges with a reviewed lockfile.", confidence="low", evidence={"dependency": line}))
    if "dependencies = []" not in text and not any((root / lock).exists() for lock in ("requirements.txt", "requirements.lock", "uv.lock", "poetry.lock", "Pipfile.lock")):
        report.add(Issue(file=rel, category="SUPPLY030: dependency ranges without lockfile", severity=Severity.MEDIUM, detector="supply_chain_audit", description="Python dependencies are declared but no common lockfile was found.", recommendation="Add a lockfile or generate a pinned deploy requirements artifact.", confidence="medium"))


def _audit_package_json(root: Path, path: Path, report: Report) -> None:
    try:
        data = json.loads(_read(path))
    except json.JSONDecodeError:
        return
    rel = _rel(path, root)
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec_s = str(spec)
            if spec_s.startswith(("^", "~", ">", "*")):
                report.add(Issue(file=rel, category="SUPPLY040: broad npm dependency constraint", severity=Severity.MEDIUM, detector="supply_chain_audit", description=f"npm dependency {name!r} uses broad range {spec_s!r}.", recommendation="Use lockfiles and reviewed dependency update policy for deploy builds.", confidence="medium", evidence={"dependency": name, "version": spec_s}))
            if spec_s.startswith(("http://", "https://", "git+")):
                report.add(Issue(file=rel, category="SUPPLY041: direct npm URL dependency", severity=Severity.HIGH, detector="supply_chain_audit", description=f"npm dependency {name!r} uses a direct URL/git source.", recommendation="Pin immutable commits and review provenance.", confidence="medium", evidence={"dependency": name, "version": spec_s}))


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(errors="replace")


def _is_ignored(path: Path) -> bool:
    ignored = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}
    return any(part in ignored for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
