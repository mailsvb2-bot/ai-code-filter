from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class CIProfileSummary:
    profiles: int
    commands: int
    strict_profiles: int

    def to_dict(self) -> dict[str, int]:
        return {"profiles": self.profiles, "commands": self.commands, "strict_profiles": self.strict_profiles}


def audit_ci_profiles(project: str | Path, *, profiles_path: str | Path | None = None) -> tuple[Report, CIProfileSummary]:
    root = Path(project).resolve()
    path = Path(profiles_path).resolve() if profiles_path else root / "docs" / "CI_PROFILES.json"
    report = Report()
    if not path.exists():
        report.add(Issue(file=str(path), category="CIP001: missing CI profiles", severity=Severity.MEDIUM, detector="ci_profiles", description="Machine-readable CI profiles are missing.", recommendation="Create docs/CI_PROFILES.json with quick/standard/release gate profiles.", confidence="high"))
        return FindingCore().process(report).report, CIProfileSummary(0, 0, 0)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.add(Issue(file=str(path), category="CIP002: invalid CI profiles JSON", severity=Severity.HIGH, detector="ci_profiles", description=f"CI profiles JSON is invalid: {exc}.", recommendation="Fix docs/CI_PROFILES.json.", confidence="high"))
        return FindingCore().process(report).report, CIProfileSummary(0, 0, 0)
    compat = _compat_commands(root)
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict) or not profiles:
        report.add(Issue(file=str(path), category="CIP003: no CI profiles declared", severity=Severity.HIGH, detector="ci_profiles", description="CI profile registry does not declare any profiles.", recommendation="Declare at least quick, standard and release profiles.", confidence="high"))
        return FindingCore().process(report).report, CIProfileSummary(0, 0, 0)
    total_commands = 0
    strict_profiles = 0
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            report.add(Issue(file=str(path), category="CIP004: invalid CI profile", severity=Severity.MEDIUM, detector="ci_profiles", description=f"CI profile {name!r} must be an object.", recommendation="Use {commands:[...], strict:true/false} profile objects.", confidence="high"))
            continue
        commands = profile.get("commands", [])
        if not isinstance(commands, list) or not commands:
            report.add(Issue(file=str(path), category="CIP005: empty CI profile", severity=Severity.MEDIUM, detector="ci_profiles", description=f"CI profile {name!r} has no commands.", recommendation="Add deterministic audit commands to the profile.", confidence="high"))
            continue
        total_commands += len(commands)
        if bool(profile.get("strict", False)):
            strict_profiles += 1
        for command in commands:
            cmd = str(command).split()[0]
            if cmd not in compat:
                report.add(Issue(file=str(path), category="CIP010: CI profile command not compatibility-protected", severity=Severity.HIGH, detector="ci_profiles", description=f"CI profile {name!r} uses command {cmd!r}, but compatibility registry does not protect it.", recommendation="Add the command to docs/COMPATIBILITY_REGRESSIONS.json or remove it from CI profiles.", confidence="high", evidence={"profile": name, "command": command}))
    for required in ("quick", "standard", "release"):
        if required not in profiles:
            report.add(Issue(file=str(path), category="CIP020: missing standard CI profile", severity=Severity.MEDIUM, detector="ci_profiles", description=f"Standard profile {required!r} is missing.", recommendation="Declare quick, standard and release profiles so quality gates are reproducible.", confidence="high"))
    return FindingCore().process(report).report, CIProfileSummary(len(profiles), total_commands, strict_profiles)


def write_ci_profile_summary(path: str | Path | None, summary: CIProfileSummary, report: Report) -> None:
    """Write a JSON summary when path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"ci_profiles": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _compat_commands(root: Path) -> set[str]:
    path = root / "docs" / "COMPATIBILITY_REGRESSIONS.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return {str(x) for x in data.get("required_commands", []) if isinstance(x, str)}
