from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Issue, Report, Severity

DEFAULT_CORPUS = [
    {"name": "django", "url": "https://github.com/django/django", "profiles": ["django"]},
    {"name": "flask", "url": "https://github.com/pallets/flask", "profiles": ["flask"]},
    {"name": "fastapi", "url": "https://github.com/fastapi/fastapi", "profiles": ["fastapi"]},
    {"name": "sqlalchemy", "url": "https://github.com/sqlalchemy/sqlalchemy", "profiles": ["sqlalchemy"]},
    {"name": "aiogram", "url": "https://github.com/aiogram/aiogram", "profiles": ["messaging-bot"]},
    {"name": "requests", "url": "https://github.com/psf/requests", "profiles": ["generic"]},
    {"name": "urllib3", "url": "https://github.com/urllib3/urllib3", "profiles": ["generic"]},
    {"name": "pydantic", "url": "https://github.com/pydantic/pydantic", "profiles": ["generic"]},
    {"name": "pytest", "url": "https://github.com/pytest-dev/pytest", "profiles": ["generic"]},
    {"name": "black", "url": "https://github.com/psf/black", "profiles": ["generic"]},
    {"name": "ruff", "url": "https://github.com/astral-sh/ruff", "profiles": ["generic"]},
    {"name": "mypy", "url": "https://github.com/python/mypy", "profiles": ["generic"]},
    {"name": "pyright", "url": "https://github.com/microsoft/pyright", "profiles": ["generic"]},
    {"name": "semgrep", "url": "https://github.com/semgrep/semgrep", "profiles": ["generic"]},
    {"name": "bandit", "url": "https://github.com/PyCQA/bandit", "profiles": ["generic"]},
    {"name": "ansible", "url": "https://github.com/ansible/ansible", "profiles": ["generic"]},
    {"name": "sentry", "url": "https://github.com/getsentry/sentry", "profiles": ["django"]},
    {"name": "home-assistant", "url": "https://github.com/home-assistant/core", "profiles": ["generic"]},
    {"name": "superset", "url": "https://github.com/apache/superset", "profiles": ["flask", "sqlalchemy"]},
    {"name": "airflow", "url": "https://github.com/apache/airflow", "profiles": ["flask", "sqlalchemy"]},
]

@dataclass(frozen=True)
class CorpusSummary:
    projects: int
    local_paths: int
    remote_only: int
    profiles: dict[str, int]
    def to_dict(self) -> dict[str, Any]:
        return {"projects": self.projects, "local_paths": self.local_paths, "remote_only": self.remote_only, "profiles": self.profiles}

def write_default_corpus(path: str | Path) -> None:
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"schema": "ai-code-filter.real-world-corpus", "minimum_projects": 20, "projects": DEFAULT_CORPUS}, ensure_ascii=False, indent=2), encoding="utf-8")

def audit_corpus_manifest(path: str | Path, *, min_projects: int = 20, require_local_paths: bool = False) -> tuple[Report, CorpusSummary]:
    report = Report(); p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        report.add(Issue(file=str(p), category="CORPUS001: invalid corpus manifest", severity=Severity.HIGH, detector="real_world_corpus", description=f"Cannot read corpus manifest: {exc}", recommendation="Write a valid JSON corpus manifest with a projects array.", confidence="high"))
        return report, CorpusSummary(0, 0, 0, {})
    projects = data.get("projects", []) if isinstance(data, dict) else []
    if len(projects) < min_projects:
        report.add(Issue(file=str(p), category="CORPUS002: insufficient real-world corpus size", severity=Severity.HIGH, detector="real_world_corpus", description=f"Corpus has {len(projects)} projects; required minimum is {min_projects}.", recommendation="Use 20-50 diverse open-source projects for recall/precision benchmarking.", confidence="high"))
    profiles: dict[str, int] = {}; local_paths = 0
    for idx, item in enumerate(projects):
        if not isinstance(item, dict) or not item.get("name") or not (item.get("url") or item.get("path")):
            report.add(Issue(file=str(p), category="CORPUS003: malformed corpus project", severity=Severity.MEDIUM, detector="real_world_corpus", description=f"Project entry #{idx} lacks name and url/path.", recommendation="Each project needs name and url or local path.", confidence="high", evidence={"entry": item}))
            continue
        if item.get("path"):
            if Path(str(item["path"])).exists(): local_paths += 1
            else: report.add(Issue(file=str(p), category="CORPUS004: local corpus path missing", severity=Severity.MEDIUM, detector="real_world_corpus", description=f"Local corpus path does not exist: {item['path']}", recommendation="Clone/sync the corpus project or remove the stale path.", confidence="high"))
        for profile in item.get("profiles", ["generic"]):
            profiles[str(profile)] = profiles.get(str(profile), 0) + 1
    if require_local_paths and local_paths < min_projects:
        report.add(Issue(file=str(p), category="CORPUS005: local corpus not materialized", severity=Severity.HIGH, detector="real_world_corpus", description=f"Only {local_paths} local corpus paths are present.", recommendation="Clone the declared projects and set path for each entry before running offline benchmark proof.", confidence="high"))
    return report, CorpusSummary(len(projects), local_paths, len(projects) - local_paths, dict(sorted(profiles.items())))
