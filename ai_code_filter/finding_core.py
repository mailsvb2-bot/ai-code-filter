from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import Issue, Report, Severity


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class FindingPolicy:
    """Central policy for post-analysis issue decisions.

    Analyzers produce raw issues. FindingCore is the only place that decides
    stable fingerprints, deduplication, suppression application, baseline/new
    issue gates, and CI exit policy.
    """

    max_critical: int | None = None
    max_high: int | None = None
    max_medium: int | None = None
    max_low: int | None = None
    fail_on_new: str | None = None
    baseline_report: Path | None = None


@dataclass(frozen=True)
class FindingCoreResult:
    report: Report
    gate_failures: tuple[str, ...] = ()
    suppressed_count: int = 0
    duplicate_count: int = 0

    def should_fail_ci(self) -> bool:
        return self.report.has_blocking_issues() or bool(self.gate_failures)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str | None = None
    rule_id: str | None = None
    file: str | None = None
    reason: str = ""
    owner: str = ""
    expires: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Suppression":
        return cls(
            fingerprint=raw.get("fingerprint"),
            rule_id=raw.get("rule_id"),
            file=raw.get("file"),
            reason=str(raw.get("reason", "")),
            owner=str(raw.get("owner", "")),
            expires=raw.get("expires"),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.fingerprint and not self.rule_id:
            errors.append("suppression must define fingerprint or rule_id")
        if not self.reason.strip():
            errors.append("suppression reason is required")
        if not self.owner.strip():
            errors.append("suppression owner is required")
        if not self.expires:
            errors.append("suppression expires is required")
        else:
            try:
                exp = date.fromisoformat(self.expires)
            except ValueError:
                errors.append(f"invalid expires date: {self.expires}")
            else:
                if exp < datetime.now(timezone.utc).date():
                    errors.append(f"expired suppression: {self.expires}")
        return errors

    def matches(self, issue: Issue, core: "FindingCore") -> bool:
        if self.file and self.file != issue.file:
            return False
        if self.fingerprint and self.fingerprint == core.fingerprint(issue):
            return True
        if self.rule_id and issue.category.startswith(f"{self.rule_id}:"):
            return True
        return False


class FindingCore:
    """Single decision center for normalized findings.

    Keep analyzers focused on detection. All post-processing decisions live
    here so baseline, suppression, dedupe and exit semantics cannot drift into
    multiple competing mini-decision layers.
    """

    def normalize(self, issue: Issue) -> Issue:
        confidence = (issue.confidence or "medium").lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"
        evidence = dict(issue.evidence or {})
        evidence.setdefault("fingerprint_basis", self._fingerprint_basis(issue))
        evidence.setdefault("decision_core", "FindingCore")
        if issue.confidence == confidence and issue.evidence == evidence:
            return issue
        return Issue(
            file=issue.file,
            category=issue.category,
            severity=issue.severity,
            detector=issue.detector,
            description=issue.description,
            recommendation=issue.recommendation,
            location=issue.location,
            line_number=issue.line_number,
            confidence=confidence,
            evidence=evidence,
        )

    def fingerprint(self, issue: Issue) -> str:
        raw = "\n".join(self._fingerprint_basis(issue))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def dedupe(self, issues: Iterable[Issue]) -> tuple[list[Issue], int]:
        seen: set[str] = set()
        deduped: list[Issue] = []
        duplicate_count = 0
        for raw_issue in issues:
            issue = self.normalize(raw_issue)
            fp = self.fingerprint(issue)
            if fp in seen:
                duplicate_count += 1
                continue
            seen.add(fp)
            deduped.append(issue)
        return deduped, duplicate_count

    def load_suppressions(self, path: Path | None) -> tuple[list[Suppression], list[str]]:
        if not path:
            return [], []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return [], [f"suppression file not found: {path}"]
        except json.JSONDecodeError as exc:
            return [], [f"invalid suppression JSON: {exc}"]
        raws = data.get("suppressions", data if isinstance(data, list) else [])
        if not isinstance(raws, list):
            return [], ["suppression file must be a list or {'suppressions': [...]} object"]
        suppressions = [Suppression.from_dict(raw) for raw in raws if isinstance(raw, dict)]
        errors: list[str] = []
        for idx, suppression in enumerate(suppressions):
            errors.extend(f"suppression[{idx}]: {error}" for error in suppression.validate())
        return suppressions, errors

    def apply_suppressions(self, report: Report, suppressions: list[Suppression]) -> tuple[Report, int, list[str]]:
        if not suppressions:
            return report, 0, []
        filtered = self._clone_shell(report)
        suppressed_count = 0
        used: set[int] = set()
        for issue in report.issues:
            matched = False
            for idx, suppression in enumerate(suppressions):
                if suppression.matches(issue, self):
                    filtered.record_skip(issue.file, f"suppressed {issue.category} fingerprint={self.fingerprint(issue)}")
                    suppressed_count += 1
                    used.add(idx)
                    matched = True
                    break
            if not matched:
                filtered.add(issue)
        unused = [f"suppression[{idx}] did not match any finding" for idx in range(len(suppressions)) if idx not in used]
        return filtered, suppressed_count, unused

    def evaluate_policy(self, report: Report, policy: FindingPolicy) -> tuple[str, ...]:
        failures: list[str] = []
        summary = report.summary()
        limits = {
            "CRITICAL": policy.max_critical,
            "HIGH": policy.max_high,
            "MEDIUM": policy.max_medium,
            "LOW": policy.max_low,
        }
        for key, limit in limits.items():
            if limit is not None and summary[key] > limit:
                failures.append(f"{key} budget exceeded: {summary[key]} > {limit}")
        if policy.fail_on_new and policy.baseline_report:
            failures.extend(self._new_issue_failures(report, policy.baseline_report, policy.fail_on_new))
        return tuple(failures)

    def process(
        self,
        report: Report,
        *,
        policy: FindingPolicy | None = None,
        suppressions: list[Suppression] | None = None,
        suppression_errors: Iterable[str] = (),
    ) -> FindingCoreResult:
        normalized = self._clone_shell(report)
        deduped, duplicate_count = self.dedupe(report.issues)
        normalized.extend(deduped)
        for error in suppression_errors:
            normalized.add(Issue(
                file="<suppressions>",
                category="Suppression governance",
                severity=Severity.HIGH,
                detector="suppression_policy",
                description=error,
                recommendation="Fix the suppression file or remove the flag.",
                confidence="high",
            ))
        filtered, suppressed_count, unused_suppressions = self.apply_suppressions(normalized, suppressions or [])
        for warning in unused_suppressions:
            filtered.add(Issue(
                file="<suppressions>",
                category="Suppression governance",
                severity=Severity.HIGH,
                detector="suppression_policy",
                description=warning,
                recommendation="Remove stale suppressions or update them to match current findings.",
                confidence="high",
            ))
        gate_failures = self.evaluate_policy(filtered, policy or FindingPolicy())
        final = filtered
        for failure in gate_failures:
            final.add(Issue(
                file="<quality-gate>",
                category="Quality gate",
                severity=Severity.HIGH,
                detector="quality_gate",
                description=failure,
                recommendation="Reduce issues, update baseline deliberately, or adjust the explicit budget.",
                confidence="high",
            ))
        return FindingCoreResult(
            report=final,
            gate_failures=gate_failures,
            suppressed_count=suppressed_count,
            duplicate_count=duplicate_count,
        )

    def decide_exit_code(self, result: FindingCoreResult, *, ci: bool) -> int:
        if not ci:
            return 0
        return 1 if result.should_fail_ci() else 0

    def _new_issue_failures(self, report: Report, baseline_path: Path, fail_on_new: str) -> list[str]:
        threshold = Severity(fail_on_new.upper())
        old = self._load_baseline_fingerprints(baseline_path)
        new_blockers = [
            issue for issue in report.issues
            if self.fingerprint(issue) not in old and SEVERITY_ORDER[issue.severity] >= SEVERITY_ORDER[threshold]
        ]
        if not new_blockers:
            return []
        return [f"New {threshold.value}+ issues detected: {len(new_blockers)}"]

    def _load_baseline_fingerprints(self, path: Path) -> set[str]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return set()
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid baseline report JSON: {path}: {exc}") from exc
        fingerprints: set[str] = set()
        for raw in data.get("issues", []):
            try:
                severity = Severity(str(raw.get("severity", "MEDIUM")))
            except ValueError:
                severity = Severity.MEDIUM
            issue = Issue(
                file=str(raw.get("file", "")),
                category=str(raw.get("category", "")),
                severity=severity,
                detector=str(raw.get("detector", "unknown")),
                description=str(raw.get("description", "")),
                recommendation=str(raw.get("recommendation", "")),
                location=raw.get("location"),
                line_number=raw.get("line_number"),
                confidence=str(raw.get("confidence", "medium")),
                evidence=raw.get("evidence") if isinstance(raw.get("evidence"), dict) else None,
            )
            fingerprints.add(self.fingerprint(issue))
        return fingerprints

    def _clone_shell(self, report: Report) -> Report:
        cloned = Report()
        cloned.failed_files = list(report.failed_files)
        cloned.skipped_files = list(report.skipped_files)
        return cloned

    def _fingerprint_basis(self, issue: Issue) -> tuple[str, ...]:
        return (
            issue.file,
            issue.category,
            issue.detector,
            str(issue.line_number or ""),
            issue.location or "",
            issue.description,
        )
