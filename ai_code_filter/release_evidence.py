from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .finding_core import FindingCore
from .models import Issue, Report, Severity

_REQUIRED = (
    "README.md",
    "MANIFEST.sha256",
    "docs/LIMITATIONS.json",
    "docs/RULE_OWNERSHIP.json",
    "docs/COMPATIBILITY_REGRESSIONS.json",
    "docs/QUALITY_POLICY.json",
    "docs/CI_PROFILES.json",
    "docs/GREP_AUDIT_PATTERNS.json",
)


@dataclass(frozen=True)
class ReleaseEvidenceSummary:
    required_artifacts: int
    manifest_entries: int
    missing_from_manifest: int

    def to_dict(self) -> dict[str, int]:
        return {"required_artifacts": self.required_artifacts, "manifest_entries": self.manifest_entries, "missing_from_manifest": self.missing_from_manifest}


def audit_release_evidence(project: str | Path) -> tuple[Report, ReleaseEvidenceSummary]:
    root = Path(project).resolve()
    report = Report()
    manifest = root / "MANIFEST.sha256"
    manifest_entries = _manifest_entries(manifest)
    missing_from_manifest = 0
    for rel in _REQUIRED:
        path = root / rel
        if not path.exists():
            report.add(Issue(file=str(path), category="REL001: required release evidence artifact missing", severity=Severity.HIGH, detector="release_evidence", description=f"Required release evidence artifact {rel!r} is missing.", recommendation="Create the artifact before publishing a release archive.", confidence="high", evidence={"artifact": rel}))
            continue
        if rel != "MANIFEST.sha256" and rel not in manifest_entries:
            missing_from_manifest += 1
            report.add(Issue(file=str(path), category="REL002: release evidence not covered by manifest", severity=Severity.MEDIUM, detector="release_evidence", description=f"Required artifact {rel!r} is not present in MANIFEST.sha256.", recommendation="Regenerate MANIFEST.sha256 after release evidence changes.", confidence="high", evidence={"artifact": rel}))
    for json_rel in ("docs/LIMITATIONS.json", "docs/RULE_OWNERSHIP.json", "docs/COMPATIBILITY_REGRESSIONS.json", "docs/QUALITY_POLICY.json", "docs/CI_PROFILES.json"):
        path = root / json_rel
        if path.exists():
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                report.add(Issue(file=str(path), category="REL010: invalid release evidence JSON", severity=Severity.HIGH, detector="release_evidence", description=f"Release evidence JSON {json_rel!r} is invalid: {exc}.", recommendation="Fix the JSON artifact before publishing.", confidence="high"))
    return FindingCore().process(report).report, ReleaseEvidenceSummary(len(_REQUIRED), len(manifest_entries), missing_from_manifest)


def write_release_evidence_summary(path: str | Path | None, summary: ReleaseEvidenceSummary, report: Report) -> None:
    """Write a JSON summary when path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"release_evidence": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _manifest_entries(path: Path) -> set[str]:
    if not path.exists():
        return set()
    entries: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            entries.add(parts[1])
    return entries
