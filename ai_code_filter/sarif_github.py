from __future__ import annotations

import json
from pathlib import Path

from .models import Issue, Report, Severity

def audit_github_sarif(path: str | Path) -> Report:
    report = Report(); p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        report.add(Issue(file=str(p), category="SARIF001: invalid SARIF JSON", severity=Severity.HIGH, detector="sarif_github", description=f"SARIF is not readable JSON: {exc}", recommendation="Generate SARIF 2.1.0 JSON before upload.", confidence="high")); return report
    if data.get("version") != "2.1.0":
        report.add(Issue(file=str(p), category="SARIF002: unsupported SARIF version", severity=Severity.HIGH, detector="sarif_github", description="GitHub Code Scanning expects SARIF 2.1.0.", recommendation="Regenerate the report with ai-code-filter SARIF writer.", confidence="high"))
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list) or not runs:
        report.add(Issue(file=str(p), category="SARIF003: missing runs", severity=Severity.HIGH, detector="sarif_github", description="SARIF has no runs array.", recommendation="Upload a complete SARIF file with tool driver and results.", confidence="high")); return report
    for idx, run in enumerate(runs):
        driver = (((run or {}).get("tool") or {}).get("driver") or {}) if isinstance(run, dict) else {}
        if not driver.get("name") or not isinstance(driver.get("rules", []), list):
            report.add(Issue(file=str(p), category="SARIF004: incomplete tool driver", severity=Severity.HIGH, detector="sarif_github", description=f"Run #{idx} lacks driver name/rules.", recommendation="Include tool.driver.name and tool.driver.rules for Code Scanning UX.", confidence="high"))
        for ridx, result in enumerate(run.get("results", []) if isinstance(run, dict) else []):
            if not result.get("ruleId"):
                report.add(Issue(file=str(p), category="SARIF005: result missing ruleId", severity=Severity.MEDIUM, detector="sarif_github", description=f"Result #{ridx} has no ruleId.", recommendation="Set ruleId for every result.", confidence="high"))
            locs = result.get("locations", [])
            if not locs or not (((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")):
                report.add(Issue(file=str(p), category="SARIF006: result missing artifact URI", severity=Severity.MEDIUM, detector="sarif_github", description=f"Result #{ridx} has no artifactLocation.uri.", recommendation="Set file URI and region for every result.", confidence="high"))
            if not result.get("partialFingerprints"):
                report.add(Issue(file=str(p), category="SARIF007: missing stable fingerprint", severity=Severity.LOW, detector="sarif_github", description=f"Result #{ridx} has no partialFingerprints.", recommendation="Provide stable fingerprints so GitHub can track alerts across commits.", confidence="medium"))
    return report
