from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity

OWNER_RE = re.compile(r"(?im)(?:^\s*#\s*)?(?:owner|owners|maintainer|responsible)\s*[:=]\s*([A-Za-z0-9_.@/-]+)")
ANTI_OWNER_RE = re.compile(r"(?im)(?:do\s+not\s+use|bypass|ignore|disable)\s+(?:owner|approval|review|governance|guard)")

@dataclass(frozen=True)
class OwnershipConflictSummary:
    files_scanned: int
    owner_markers: int
    conflicts: int
    counteraction_signals: int

    def to_dict(self) -> dict[str, int]:
        return {"files_scanned": self.files_scanned, "owner_markers": self.owner_markers, "conflicts": self.conflicts, "counteraction_signals": self.counteraction_signals}


def audit_ownership_conflicts(project: str | Path) -> tuple[Report, OwnershipConflictSummary]:
    root = Path(project).resolve()
    report = Report()
    files = [p for p in root.rglob("*") if p.is_file() and p.suffix in {".py", ".md", ".txt", ".yml", ".yaml", ".json", ".toml"} and not _ignored(p)]
    owner_by_file: dict[str, set[str]] = {}
    markers = conflicts = counter = 0
    codeowners = _load_codeowners(root)
    for path in files:
        rel = _rel(path, root)
        text = path.read_text(encoding="utf-8", errors="ignore")
        owners = {m.group(1).strip() for m in OWNER_RE.finditer(text)}
        if owners:
            markers += len(owners)
            owner_by_file[rel] = owners
        implied = _implied_codeowners(rel, codeowners)
        if owners and implied and owners.isdisjoint(implied):
            conflicts += 1
            report.add(Issue(file=rel, category="OWN001: conflicting owner markers", severity=Severity.HIGH, detector="ownership_conflicts", description="Inline owner markers contradict CODEOWNERS/registry ownership for this file.", recommendation="Choose one canonical owner or document shared ownership with explicit rationale.", confidence="medium", evidence={"inline_owners": sorted(owners), "codeowners": sorted(implied)}))
        if ANTI_OWNER_RE.search(text):
            counter += 1
            report.add(Issue(file=rel, category="OWN010: ownership counteraction signal", severity=Severity.MEDIUM, detector="ownership_conflicts", description="Text suggests bypassing or disabling owner/governance review.", recommendation="Remove bypass language or document a reviewed emergency procedure with expiry/owner.", confidence="medium"))
    return FindingCore().process(report).report, OwnershipConflictSummary(len(files), markers, conflicts, counter)


def write_ownership_conflict_summary(path: str | Path | None, summary: OwnershipConflictSummary, report: Report) -> None:
    """Write a summary JSON file; returns None when no path is supplied."""
    if not path: return
    out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"ownership_conflicts": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_codeowners(root: Path) -> list[tuple[str, set[str]]]:
    paths = [root / "CODEOWNERS", root / ".github" / "CODEOWNERS", root / "docs" / "CODEOWNERS"]
    rows: list[tuple[str, set[str]]] = []
    for p in paths:
        if not p.exists(): continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = line.split()
            if len(parts) >= 2:
                rows.append((parts[0].lstrip("/"), set(parts[1:])))
    return rows


def _implied_codeowners(rel: str, rows: list[tuple[str, set[str]]]) -> set[str]:
    owners: set[str] = set()
    for pattern, row_owners in rows:
        prefix = pattern.rstrip("*").rstrip("/")
        if rel.startswith(prefix) or pattern in {"*", "**"}:
            owners |= row_owners
    return owners


def _ignored(path: Path) -> bool:
    return any(part in {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build", "tests"} for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try: return str(path.resolve().relative_to(root.resolve()))
    except ValueError: return str(path)
