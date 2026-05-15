from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .finding_core import FindingCore
from .models import Issue, Report, Severity
from .pipeline import AnalysisPipeline
from .config import RuntimeConfig, DEFAULT_EXTENSIONS, DEFAULT_MODEL


@dataclass(frozen=True)
class ChangedFilesSummary:
    changed_files: int
    analyzed_files: int
    missing_files: int

    def to_dict(self) -> dict[str, int]:
        return {"changed_files": self.changed_files, "analyzed_files": self.analyzed_files, "missing_files": self.missing_files}


def audit_changed_files(project: str | Path, *, changed_files: Iterable[str] = (), changed_files_list: str | Path | None = None, extensions: Iterable[str] = DEFAULT_EXTENSIONS) -> tuple[Report, ChangedFilesSummary]:
    root = Path(project).resolve()
    report = Report()
    raw = list(changed_files)
    if changed_files_list:
        path = Path(changed_files_list)
        if not path.is_absolute():
            path = root / path
        if path.exists():
            raw.extend([line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()])
        else:
            report.add(Issue(file=str(path), category="CHG001: changed-files list missing", severity=Severity.HIGH, detector="changed_files", description="The changed-files list does not exist.", recommendation="Provide a valid --changed-files-list or explicit --changed-file values.", confidence="high"))
    if not raw:
        report.add(Issue(file=str(root), category="CHG002: no changed files provided", severity=Severity.MEDIUM, detector="changed_files", description="No changed files were provided for changed-files audit.", recommendation="Pass --changed-file or --changed-files-list; otherwise use full-project analyze.", confidence="high"))
        return FindingCore().process(report).report, ChangedFilesSummary(0, 0, 0)
    selected: list[Path] = []
    missing = 0
    for rel in raw:
        p = (root / rel).resolve()
        try:
            p.relative_to(root)
        except ValueError:
            report.add(Issue(file=str(rel), category="CHG003: changed file escapes project root", severity=Severity.HIGH, detector="changed_files", description=f"Changed path {rel!r} resolves outside the project root.", recommendation="Reject changed-file manifests with path traversal.", confidence="high", evidence={"path": rel}))
            continue
        if not p.exists():
            missing += 1
            report.add(Issue(file=str(rel), category="CHG004: changed file missing", severity=Severity.LOW, detector="changed_files", description=f"Changed file {rel!r} is not present; it may have been deleted.", recommendation="Handle deleted files explicitly in the CI workflow.", confidence="medium", evidence={"path": rel}))
            continue
        if p.is_file() and p.suffix in set(extensions):
            selected.append(p)
    if selected:
        cfg = RuntimeConfig(model=DEFAULT_MODEL, extensions=tuple(extensions), enable_ai_review=False, enable_drift=False, workers=1)
        analyzed = AnalysisPipeline(cfg).analyze_paths([str(p) for p in selected])
        for issue in analyzed.issues:
            report.add(issue)
        for failed in analyzed.failed_files:
            report.failed_files.append(failed)
        for skipped in analyzed.skipped_files:
            report.skipped_files.append(skipped)
    return FindingCore().process(report).report, ChangedFilesSummary(len(raw), len(selected), missing)


def write_changed_files_summary(path: str | Path | None, summary: ChangedFilesSummary, report: Report) -> None:
    """Write a JSON summary when path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"changed_files": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")
