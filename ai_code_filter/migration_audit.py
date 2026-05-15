from __future__ import annotations

import json
import re
from pathlib import Path

from .finding_core import FindingCore
from .models import Issue, Report, Severity


def audit_migrations(project: str | Path) -> Report:
    root = Path(project).resolve()
    report = Report()
    migration_files = _migration_files(root)
    db_config_present = _has_db_config(root)
    if db_config_present and not migration_files:
        report.add(Issue(
            file=str(root),
            category="MIG001: DB config without migrations",
            severity=Severity.HIGH,
            detector="migration_audit",
            description="Project appears to configure a database but no migration files were found.",
            recommendation="Add reviewed migrations or document why the project is schema-less/read-only.",
            confidence="medium",
            evidence={"db_config_present": True},
        ))
    versions: set[str] = set()
    for path in migration_files:
        rel = _rel(path, root)
        text = _read(path)
        version = _extract_revision(text, path.name)
        if version:
            if version in versions:
                report.add(Issue(file=rel, category="MIG010: duplicate migration revision", severity=Severity.HIGH, detector="migration_audit", description=f"Duplicate migration revision {version!r}.", recommendation="Ensure migration revisions are unique and linear/merged intentionally.", confidence="high", evidence={"revision": version}))
            versions.add(version)
        if re.search(r"DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE\s+TABLE|DELETE\s+FROM", text, re.IGNORECASE):
            report.add(Issue(file=rel, category="MIG020: destructive migration operation", severity=Severity.HIGH, detector="migration_audit", description="Migration contains destructive SQL/data operation.", recommendation="Add backup/rollback/approval evidence before production use.", confidence="medium", evidence={"pattern": "drop/truncate/delete"}))
        if "sqlite" in text.lower() and re.search(r"postgres|postgresql", text, re.IGNORECASE):
            report.add(Issue(file=rel, category="MIG030: mixed SQLite/Postgres migration semantics", severity=Severity.HIGH, detector="migration_audit", description="Migration references both SQLite and Postgres semantics.", recommendation="Split backend-specific migrations or enforce one production backend contract.", confidence="medium"))
        if "def downgrade" not in text and "down_revision" in text:
            report.add(Issue(file=rel, category="MIG040: Alembic migration lacks downgrade", severity=Severity.MEDIUM, detector="migration_audit", description="Alembic-like migration lacks a downgrade function.", recommendation="Add downgrade or document irreversible migration rationale.", confidence="medium"))
    return FindingCore().process(report).report


def write_migration_summary(path: str | Path | None, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _migration_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or _is_ignored(path):
            continue
        rel_parts = [part.lower() for part in path.resolve().relative_to(root.resolve()).parts]
        lowered_name = path.name.lower()
        is_migration_area = any(part in {"migrations", "migration", "alembic", "versions"} for part in rel_parts[:-1])
        is_migration_file = re.match(r"^[0-9]{4,}.*\.(py|sql)$", lowered_name) is not None or lowered_name.endswith(("_migration.py", ".sql"))
        if (is_migration_area or is_migration_file) and path.suffix in {".py", ".sql"}:
            out.append(path)
    return sorted(out)


def _has_db_config(root: Path) -> bool:
    for path in root.rglob("*"):
        if not path.is_file() or _is_ignored(path) or _is_test_path(path, root) or path.suffix.lower() not in {".py", ".env", ".toml", ".yaml", ".yml", ".json", ".ini"}:
            continue
        text = _read(path).lower()
        if re.search(r"\b(database_url|postgres_dsn|db_engine)\b\s*[:=]", text) or re.search(r"(sqlite|postgresql)://", text):
            if "detector" in text and "recommendation" in text and path.name.endswith("_audit.py"):
                continue
            return True
    return False


def _extract_revision(text: str, name: str) -> str | None:
    match = re.search(r"revision\s*=\s*['\"]([^'\"]+)", text)
    if match:
        return match.group(1)
    match = re.match(r"(\d{4,}|[a-f0-9]{8,})", name)
    return match.group(1) if match else None


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


def _is_test_path(path: Path, root: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        parts = path.parts
    return "tests" in parts or path.name.startswith("test_") or path.name.endswith("_test.py")
