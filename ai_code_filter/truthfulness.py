from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Issue, Report, Severity

OVERCLAIM_RE = re.compile(r"(?i)\b(production[- ]ready|complete static analysis|full taint analysis|zero false negatives|guaranteed safe|final production)\b")
LIMITED_OK_RE = re.compile(r"(?i)\b(not production[- ]ready|not a full static analyzer|limitations?|ci helper|static audit helper)\b")


def run_truthfulness_gate(project_root: str | Path) -> Report:
    root = Path(project_root)
    report = Report()
    has_limitations = (root / "docs" / "LIMITATIONS.json").exists()
    docs = sorted((root / "docs").glob("*.md")) if (root / "docs").exists() else []
    for path in [root / "README.md", *docs]:
        if not path.exists() or not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for idx, line in enumerate(lines, start=1):
            if not OVERCLAIM_RE.search(line):
                continue
            window = "\n".join(lines[max(0, idx - 3): idx + 2])
            if LIMITED_OK_RE.search(window) or has_limitations:
                continue
            report.add(Issue(
                file=str(path.relative_to(root)),
                category="HON001: Unqualified capability overclaim",
                severity=Severity.HIGH,
                detector="truthfulness_gate",
                description="Documentation makes a strong production/completeness claim without nearby limitation wording or docs/LIMITATIONS.json.",
                recommendation="Qualify the claim with tested scope, evidence, and explicit limitations.",
                location=line.strip(),
                line_number=idx,
                confidence="medium",
                evidence={"line": line.strip(), "limitations_registry_present": has_limitations},
            ))
    return report


def validate_limitations_file(project_root: str | Path) -> Report:
    root = Path(project_root)
    report = Report()
    path = root / "docs" / "LIMITATIONS.json"
    if not path.exists():
        report.add(Issue(file="docs/LIMITATIONS.json", category="HON002: Missing limitations registry", severity=Severity.MEDIUM, detector="truthfulness_gate", description="No machine-readable limitations registry found.", recommendation="Add docs/LIMITATIONS.json to document unsupported analysis scopes.", confidence="high"))
        return report
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.add(Issue(file="docs/LIMITATIONS.json", category="HON003: Invalid limitations registry", severity=Severity.HIGH, detector="truthfulness_gate", description=f"Invalid JSON: {exc}", recommendation="Fix JSON syntax.", confidence="high"))
        return report
    for key in ("engine", "dataflow", "symbol_resolution", "production_claim"):
        if key not in data:
            report.add(Issue(file="docs/LIMITATIONS.json", category="HON004: Incomplete limitations registry", severity=Severity.MEDIUM, detector="truthfulness_gate", description=f"Missing limitations key: {key}", recommendation="Keep limitations explicit and machine-readable.", confidence="high", evidence={"missing_key": key}))
    return report
