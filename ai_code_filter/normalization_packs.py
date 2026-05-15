from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .external_normalization import normalize_external_findings
from .models import Issue, Report, Severity

FIRST_CLASS_TOOLS = ("semgrep", "bandit", "ruff", "pyright")

@dataclass(frozen=True)
class NormalizationPack:
    tool: str
    required_fields: tuple[str, ...]
    category_prefix: str
    sarif_rule_namespace: str
    severity_model: str
    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "required_fields": list(self.required_fields), "category_prefix": self.category_prefix, "sarif_rule_namespace": self.sarif_rule_namespace, "severity_model": self.severity_model}

PACKS = {
    "semgrep": NormalizationPack("semgrep", ("results[].check_id", "results[].path", "results[].start.line", "results[].extra.message"), "external.semgrep", "semgrep", "extra.severity -> native severity"),
    "bandit": NormalizationPack("bandit", ("results[].test_id", "results[].filename", "results[].line_number", "results[].issue_text"), "external.bandit", "bandit", "issue_severity + issue_confidence"),
    "ruff": NormalizationPack("ruff", ("[].code", "[].filename", "[].location.row", "[].message"), "external.ruff", "ruff", "lint findings default to MEDIUM"),
    "pyright": NormalizationPack("pyright", ("generalDiagnostics[].rule", "generalDiagnostics[].file", "generalDiagnostics[].range.start.line", "generalDiagnostics[].message"), "external.pyright", "pyright", "type diagnostic severity mapping"),
}

def list_packs() -> dict[str, Any]:
    return {"first_class_normalization_packs": [PACKS[name].to_dict() for name in FIRST_CLASS_TOOLS]}

def normalize_with_pack(tool: str, path: str | Path) -> Report:
    if tool not in PACKS:
        report = Report()
        report.add(Issue(file=str(path), category="NORMPACK001: unknown normalization pack", severity=Severity.HIGH, detector="normalization_pack", description=f"Unknown normalization pack: {tool}.", recommendation=f"Use one of: {', '.join(FIRST_CLASS_TOOLS)}.", confidence="high"))
        return report
    payload = Path(path).read_text(encoding="utf-8")
    report, _summary = normalize_external_findings(tool, payload)
    return report

def write_pack_summary(path: str | Path | None) -> None:
    if path:
        Path(path).write_text(json.dumps(list_packs(), ensure_ascii=False, indent=2), encoding="utf-8")
