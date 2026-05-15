from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class ZipFixtureSummary:
    zip_files: int
    duplicate_archives: int
    intentional_duplicates: int
    unmarked_duplicates: int

    def to_dict(self) -> dict[str, int]:
        return {"zip_files": self.zip_files, "duplicate_archives": self.duplicate_archives, "intentional_duplicates": self.intentional_duplicates, "unmarked_duplicates": self.unmarked_duplicates}


def audit_zip_fixtures(project: str | Path) -> tuple[Report, ZipFixtureSummary]:
    root = Path(project).resolve()
    report = Report()
    zips = [p for p in root.rglob("*.zip") if not _ignored(p)]
    duplicate_archives = intentional = unmarked = 0
    for path in zips:
        try:
            with zipfile.ZipFile(path) as zf:
                names = [i.filename for i in zf.infolist()]
        except zipfile.BadZipFile:
            continue
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if not duplicates:
            continue
        duplicate_archives += 1
        if _has_intentional_marker(path):
            intentional += 1
            continue
        unmarked += 1
        report.add(Issue(file=_rel(path, root), category="ZIPFIX001: unmarked duplicate zip-entry fixture", severity=Severity.HIGH, detector="zip_fixture_audit", description="Zip archive contains duplicate entry names without an intentional fixture marker.", recommendation="If intentional, add a sibling .intentional-duplicate-zip.json marker with reason/owner; otherwise fix the fixture.", confidence="high", evidence={"duplicates": duplicates[:20]}))
    return FindingCore().process(report).report, ZipFixtureSummary(len(zips), duplicate_archives, intentional, unmarked)


def write_zip_fixture_summary(path: str | Path | None, summary: ZipFixtureSummary, report: Report) -> None:
    """Write a summary JSON file; returns None when no path is supplied."""
    if not path:
        return
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"zip_fixture_audit": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _has_intentional_marker(path: Path) -> bool:
    if "duplicate" in path.name.lower() or "collision" in path.name.lower():
        return True
    marker = path.with_suffix(path.suffix + ".intentional-duplicate-zip.json")
    if not marker.exists():
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return all(data.get(k) for k in ("reason", "owner"))


def _ignored(path: Path) -> bool:
    return any(part in {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"} for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try: return str(path.resolve().relative_to(root.resolve()))
    except ValueError: return str(path)
