from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import FilePayload, Issue, Report, Severity

_TEXT_EXTENSIONS = {".py", ".env", ".example", ".sample", ".ini", ".cfg", ".conf", ".toml", ".yaml", ".yml", ".json"}
_SKIP_PARTS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules", "dist", "build"}
_CONFIG_NAMES = {
    ".env", ".env.example", ".env.sample", "env.example", "env.sample",
    "settings.py", "config.py", "database.py", "db.py", "alembic.ini",
    "pyproject.toml", "docker-compose.yml", "docker-compose.yaml",
}
_DB_ENV_RE = re.compile(r"(?i)^(DATABASE_URL|DB_URL|DB_URI|DB_DSN|DB_ENGINE|DB_BACKEND|DB_DRIVER|SQLALCHEMY_DATABASE_URI|POSTGRES(?:QL)?_DSN|POSTGRES(?:QL)?_URL|SQLITE(?:_URL|_PATH|_DB)?|DATABASE_ENGINE)$")
_SQLITE_RE = re.compile(r"(?i)(sqlite(?:\+aiosqlite)?://|sqlite3\b|aiosqlite\b|pysqlite\b|\bsqlite\b|[\w./-]+\.sqlite3?\b|[\w./-]+\.db\b)")
_POSTGRES_RE = re.compile(r"(?i)(postgresql(?:\+asyncpg|\+psycopg2?)?://|postgres://|\bpostgresql\b|\bpostgres\b|\basyncpg\b|\bpsycopg2?\b)")
_MYSQL_RE = re.compile(r"(?i)(mysql(?:\+pymysql)?://|\bmysql\b|\bmariadb\b|\bpymysql\b)")
_MIGRATION_OR_TEST_RE = re.compile(r"(?i)(test|fixture|sample|example|migration|alembic|docs?/|readme|changelog)")
_PROD_RE = re.compile(r"(?i)(prod|production|release|deploy|docker|compose|systemd|gunicorn|uvicorn)")


@dataclass(frozen=True)
class DBMarker:
    backend: str
    file: str
    line_number: int
    line: str
    source: str
    confidence: str = "medium"


@dataclass(frozen=True)
class DBConsistencySummary:
    markers: tuple[DBMarker, ...] = ()
    backends_by_file: dict[str, set[str]] = field(default_factory=dict)
    backends: set[str] = field(default_factory=set)


def audit_db_consistency(project_root: str | Path) -> Report:
    root = Path(project_root)
    payloads = _collect_payloads(root)
    return audit_db_consistency_payloads(payloads, root)


def audit_db_consistency_payloads(payloads: Iterable[FilePayload], project_root: str | Path | None = None) -> Report:
    payload_list = list(payloads)
    root = Path(project_root) if project_root else (payload_list[0].project_root if payload_list else Path("."))
    summary = summarize_db_consistency(payload_list, root)
    report = Report()
    if not summary.markers:
        return report

    for file, backends in sorted(summary.backends_by_file.items()):
        if len(backends) < 2:
            continue
        markers = [m for m in summary.markers if m.file == file]
        severity = Severity.HIGH if _is_runtime_config_file(file) else Severity.MEDIUM
        report.add(Issue(
            file=file,
            category="DB001: Mixed database backends in one file",
            severity=severity,
            detector="db_consistency",
            description=f"File references multiple database backends: {', '.join(sorted(backends))}.",
            recommendation="Split test/example backends from runtime config, or make the active backend explicit and fail-closed.",
            confidence="high" if severity is Severity.HIGH else "medium",
            evidence={"backends": sorted(backends), "markers": [_marker_dict(m) for m in markers[:8]]},
        ))

    runtime_markers = [m for m in summary.markers if _is_runtime_config_file(m.file)]
    runtime_backends = {m.backend for m in runtime_markers}
    if "sqlite" in runtime_backends and "postgres" in runtime_backends:
        report.add(Issue(
            file="<db-consistency>",
            category="DB002: Runtime DB backend mismatch",
            severity=Severity.HIGH,
            detector="db_consistency",
            description="Runtime/config surfaces reference both SQLite and Postgres.",
            recommendation="Declare a single production database contract; keep SQLite only in explicit local/test profiles and guard production against fallback.",
            confidence="high",
            evidence={"runtime_backends": sorted(runtime_backends), "markers": [_marker_dict(m) for m in runtime_markers[:12]]},
        ))

    prod_sqlite = [m for m in runtime_markers if m.backend == "sqlite" and (_PROD_RE.search(m.file) or _PROD_RE.search(m.line))]
    for marker in prod_sqlite[:5]:
        report.add(Issue(
            file=marker.file,
            category="DB003: SQLite appears in production-like config",
            severity=Severity.HIGH,
            detector="db_consistency",
            description="SQLite marker appears in a production/deploy-like database config surface.",
            recommendation="Use Postgres for production-like profiles, or make local SQLite fallback impossible when ENV=prod/production.",
            line_number=marker.line_number,
            location=marker.line,
            confidence="high",
            evidence=_marker_dict(marker),
        ))

    env_mismatch = _find_env_db_mismatch(summary.markers)
    for issue in env_mismatch:
        report.add(issue)
    return report


def summarize_db_consistency(payloads: Iterable[FilePayload], project_root: Path) -> DBConsistencySummary:
    markers: list[DBMarker] = []
    for payload in payloads:
        if _skip_payload(payload):
            continue
        markers.extend(_markers_for_payload(payload))
    backends_by_file: dict[str, set[str]] = {}
    for marker in markers:
        backends_by_file.setdefault(marker.file, set()).add(marker.backend)
    return DBConsistencySummary(markers=tuple(markers), backends_by_file=backends_by_file, backends={m.backend for m in markers})


def _collect_payloads(root: Path) -> list[FilePayload]:
    payloads: list[FilePayload] = []
    if root.is_file():
        paths = [root]
        project_root = root.parent
    else:
        paths = [p for p in root.rglob("*") if p.is_file()]
        project_root = root
    for path in paths:
        if _skip_path(path) or not _looks_text_db_surface(path):
            continue
        try:
            payloads.append(FilePayload(path=path, project_root=project_root, content=path.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, OSError):
            continue
    return payloads


def _markers_for_payload(payload: FilePayload) -> list[DBMarker]:
    markers: list[DBMarker] = []
    for line_number, raw_line in enumerate(payload.content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for backend, regex in (("sqlite", _SQLITE_RE), ("postgres", _POSTGRES_RE), ("mysql", _MYSQL_RE)):
            if regex.search(line):
                markers.append(DBMarker(backend=backend, file=payload.relative_path, line_number=line_number, line=line[:240], source=_line_source(line), confidence="high" if _line_source(line) != "free_text" else "medium"))
    # AST string constants catch database URLs embedded inside Python containers without depending on formatting.
    if payload.path.suffix == ".py":
        markers.extend(_python_constant_markers(payload))
    return _dedupe_markers(markers)


def _python_constant_markers(payload: FilePayload) -> list[DBMarker]:
    markers: list[DBMarker] = []
    try:
        tree = ast.parse(payload.content)
    except SyntaxError:
        return markers
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            for backend, regex in (("sqlite", _SQLITE_RE), ("postgres", _POSTGRES_RE), ("mysql", _MYSQL_RE)):
                if regex.search(value):
                    markers.append(DBMarker(backend=backend, file=payload.relative_path, line_number=getattr(node, "lineno", 1), line=value[:240], source="python_string_constant", confidence="high"))
    return markers


def _find_env_db_mismatch(markers: tuple[DBMarker, ...]) -> list[Issue]:
    issues: list[Issue] = []
    by_file: dict[str, list[DBMarker]] = {}
    for marker in markers:
        if _is_runtime_config_file(marker.file):
            by_file.setdefault(marker.file, []).append(marker)
    for file, file_markers in sorted(by_file.items()):
        env_backends: dict[str, set[str]] = {}
        for marker in file_markers:
            name = _env_name(marker.line)
            if not name or not _DB_ENV_RE.match(name):
                continue
            env_backends.setdefault(name, set()).add(marker.backend)
        if len(env_backends) < 2:
            continue
        all_backends = {backend for values in env_backends.values() for backend in values}
        if len(all_backends) < 2:
            continue
        issues.append(Issue(
            file=file,
            category="DB004: Conflicting database env contract",
            severity=Severity.HIGH,
            detector="db_consistency",
            description="Database-related environment contract contains different backends in the same runtime surface.",
            recommendation="Use one canonical DATABASE_URL/DB_ENGINE contract and isolate local SQLite examples from Postgres production settings.",
            confidence="high",
            evidence={"env_backends": {k: sorted(v) for k, v in env_backends.items()}, "markers": [_marker_dict(m) for m in file_markers[:8]]},
        ))
    return issues


def _env_name(line: str) -> str | None:
    cleaned = line.removeprefix("export ")
    if "=" not in cleaned:
        return None
    name = cleaned.split("=", 1)[0].strip().strip('"\'')
    return name or None


def _line_source(line: str) -> str:
    name = _env_name(line)
    if name and _DB_ENV_RE.match(name):
        return "database_env_contract"
    if "create_engine" in line or "DATABASE" in line or "DB_" in line or "SQLALCHEMY" in line:
        return "database_runtime_code"
    return "free_text"


def _is_runtime_config_file(file: str) -> bool:
    lowered = file.replace("\\", "/").lower()
    name = Path(lowered).name
    if name in {".env", ".env.example", ".env.sample", "env.example", "env.sample"}:
        return True
    if _MIGRATION_OR_TEST_RE.search(lowered) and not any(token in lowered for token in ("prod", "production", "deploy", "config", "settings")):
        return False
    return name in _CONFIG_NAMES or any(token in lowered for token in ("settings", "config", "database", "db", ".env", "docker", "compose", "systemd", "deploy", "runtime", "wiring"))


def _looks_text_db_surface(path: Path) -> bool:
    if path.name in _CONFIG_NAMES:
        return True
    suffixes = set(path.suffixes)
    if path.suffix in _TEXT_EXTENSIONS or suffixes & _TEXT_EXTENSIONS:
        return True
    return path.name.startswith(".env")


def _skip_payload(payload: FilePayload) -> bool:
    return _skip_path(payload.path) or not _looks_text_db_surface(payload.path)


def _skip_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    if parts & _SKIP_PARTS:
        return True
    lowered = str(path).replace("\\", "/").lower()
    # Avoid self-report noise from this tool's own detector strings/regression fixtures.
    if (
        Path(lowered).name.startswith("ai_code_filter_v")
        or "/ai_code_filter/" in f"/{lowered}"
        or "/tests/" in lowered
        or lowered.startswith("tests/")
        or "/docs/" in lowered
        or lowered.startswith("docs/")
    ):
        return True
    return False


def _dedupe_markers(markers: list[DBMarker]) -> list[DBMarker]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[DBMarker] = []
    for marker in markers:
        key = (marker.backend, marker.file, marker.line_number, marker.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(marker)
    return unique


def _marker_dict(marker: DBMarker) -> dict[str, object]:
    return {
        "backend": marker.backend,
        "file": marker.file,
        "line_number": marker.line_number,
        "line": marker.line,
        "source": marker.source,
        "confidence": marker.confidence,
    }


class DBConsistencyAnalyzer:
    name = "db_consistency"

    def __init__(self, payloads: list[FilePayload]) -> None:
        self.project_root = payloads[0].project_root if payloads else Path(".")
        self.anchor = payloads[0].relative_path if payloads else ""
        self.payloads = payloads
        self._issues: list[Issue] | None = None

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.relative_path != self.anchor:
            return []
        if self._issues is None:
            self._issues = list(audit_db_consistency_payloads(self.payloads, self.project_root).issues)
        return self._issues
