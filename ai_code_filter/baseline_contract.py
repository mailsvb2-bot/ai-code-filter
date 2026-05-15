from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from .models import Issue, Report, Severity


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def audit_baseline(path: str | Path, *, project_root: str | Path | None = None, max_age_days: int = 90, max_issues: int | None = None) -> Report:
    baseline_path = Path(path)
    report = Report()
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        report.add(Issue(file=str(baseline_path), category="baseline_contract.missing", severity=Severity.HIGH, detector="baseline_contract", description="Baseline file does not exist.", recommendation="Create a baseline deliberately or remove the baseline flag.", confidence="high"))
        return report
    except json.JSONDecodeError as exc:
        report.add(Issue(file=str(baseline_path), category="baseline_contract.invalid_json", severity=Severity.HIGH, detector="baseline_contract", description=str(exc), recommendation="Fix baseline JSON.", confidence="high"))
        return report
    issues = data.get("issues") if isinstance(data, dict) else None
    if not isinstance(issues, list):
        report.add(Issue(file=str(baseline_path), category="baseline_contract.invalid_shape", severity=Severity.HIGH, detector="baseline_contract", description="Baseline must contain an issues list.", recommendation="Use native ai-code-filter JSON report as baseline.", confidence="high"))
        return report
    if max_issues is not None and len(issues) > max_issues:
        report.add(Issue(file=str(baseline_path), category="baseline_contract.growth", severity=Severity.HIGH, detector="baseline_contract", description=f"Baseline contains {len(issues)} issues, budget is {max_issues}.", recommendation="Reduce baseline or deliberately raise the explicit budget.", confidence="high"))
    generated = None
    if isinstance(data.get("generated_at"), str):
        generated = _parse_time(data.get("generated_at"))
    if isinstance(data.get("metadata"), dict):
        generated = generated or _parse_time(data["metadata"].get("generated_at"))
    if isinstance(data.get("summary"), dict):
        generated = generated or _parse_time(data["summary"].get("generated_at"))
    if generated and generated < datetime.now(timezone.utc) - timedelta(days=max_age_days):
        report.add(Issue(file=str(baseline_path), category="baseline_contract.stale", severity=Severity.MEDIUM, detector="baseline_contract", description=f"Baseline is older than {max_age_days} days.", recommendation="Review and refresh or shrink the baseline.", confidence="high"))
    root = Path(project_root) if project_root else baseline_path.parent
    seen: set[str] = set()
    for idx, raw in enumerate(issues):
        if not isinstance(raw, dict):
            report.add(Issue(file=str(baseline_path), category="baseline_contract.invalid_issue", severity=Severity.HIGH, detector="baseline_contract", description=f"Issue {idx} is not an object.", recommendation="Regenerate the baseline from a native report.", confidence="high"))
            continue
        fp = raw.get("fingerprint") or (raw.get("evidence") or {}).get("fingerprint")
        if isinstance(fp, str):
            if fp in seen:
                report.add(Issue(file=str(baseline_path), category="baseline_contract.duplicate_fingerprint", severity=Severity.MEDIUM, detector="baseline_contract", description=f"Duplicate baseline fingerprint {fp}.", recommendation="Regenerate the baseline after dedupe.", confidence="high"))
            seen.add(fp)
        rel = raw.get("file")
        if isinstance(rel, str) and rel and not rel.startswith("<"):
            candidate = root / rel
            if not candidate.exists():
                report.add(Issue(file=str(baseline_path), category="baseline_contract.missing_file", severity=Severity.MEDIUM, detector="baseline_contract", description=f"Baseline references missing file: {rel}.", recommendation="Remove resolved/stale baseline entries.", confidence="high"))
    return report
