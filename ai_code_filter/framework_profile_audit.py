from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .filesystem import collect_files, infer_project_root, validate_text_file
from .models import Issue, Report, Severity

FRAMEWORK_PROFILES = ("fastapi", "flask", "django", "sqlalchemy", "aiogram", "generic-messaging")

@dataclass(frozen=True)
class FrameworkProfileSummary:
    profiles: tuple[str, ...]
    files_scanned: int
    signals: dict[str, int]
    def to_dict(self) -> dict[str, Any]:
        return {"profiles": list(self.profiles), "files_scanned": self.files_scanned, "signals": self.signals}

def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)

def audit_framework_profiles(project: str | Path, *, profiles: tuple[str, ...] = FRAMEWORK_PROFILES) -> tuple[Report, FrameworkProfileSummary]:
    root = infer_project_root([str(project)])
    files = [p for p in collect_files([str(project)], (".py",)) if p.is_file()]
    report = Report(); signals: dict[str, int] = {}; enabled = set(profiles)
    for path in files:
        try: text = validate_text_file(path)
        except Exception: continue
        rel = _rel(path, root); low = text.lower()
        def add(sig: str, sev: Severity, desc: str, rec: str, line: int = 1, loc: str = "") -> None:
            signals[sig] = signals.get(sig, 0) + 1
            report.add(Issue(file=rel, category=f"framework.{sig}", severity=sev, detector="framework_profile", description=desc, recommendation=rec, line_number=line, location=loc, confidence="medium", evidence={"profiles": sorted(enabled)}))
        for n, line in enumerate(text.splitlines(), 1):
            ll = line.lower()
            if "fastapi" in enabled and re.search(r"@\w+\.(get|post|put|delete|patch)\(", line) and "depends(" not in low and ("auth" in rel.lower() or "admin" in rel.lower()):
                add("fastapi.route_without_dependency_signal", Severity.MEDIUM, "FastAPI admin/auth route lacks visible Depends/auth signal in file.", "Add explicit dependency/auth guard or document profile suppression.", n, line.strip())
            if "flask" in enabled and "@app.route" in ll and ("login_required" not in low and "jwt_required" not in low) and ("admin" in rel.lower() or "auth" in rel.lower()):
                add("flask.route_without_auth_signal", Severity.MEDIUM, "Flask admin/auth route lacks visible auth decorator signal.", "Add login_required/JWT guard or suppress with owner evidence.", n, line.strip())
            if "django" in enabled and "csrf_exempt" in ll:
                add("django.csrf_exempt", Severity.HIGH, "Django csrf_exempt was found.", "Remove exemption or add narrow reviewed justification.", n, line.strip())
            if "sqlalchemy" in enabled and re.search(r"session\.execute\(\s*f?['\"]", line):
                add("sqlalchemy.raw_sql_string", Severity.HIGH, "SQLAlchemy session.execute appears to use raw SQL string.", "Use bound parameters/text() with validated inputs and tests.", n, line.strip())
            if {"aiogram", "generic-messaging"} & enabled and "callback_query" in ll and ".answer(" not in low:
                add("messaging.callback_without_answer", Severity.MEDIUM, "Messaging callback query surface lacks answer() signal.", "Acknowledge callbacks promptly or document why another layer does it.", n, line.strip())
    return report, FrameworkProfileSummary(tuple(sorted(enabled)), len(files), dict(sorted(signals.items())))
