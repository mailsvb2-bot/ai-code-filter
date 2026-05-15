from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .finding_core import FindingCore, FindingPolicy, Suppression, SEVERITY_ORDER
from .models import Report


_CORE = FindingCore()


def issue_fingerprint(issue):
    """Compatibility wrapper. FindingCore owns fingerprint semantics."""
    return _CORE.fingerprint(issue)


@dataclass(frozen=True)
class QualityGate:
    max_critical: int | None = None
    max_high: int | None = None
    max_medium: int | None = None
    max_low: int | None = None
    fail_on_new: str | None = None
    baseline_report: Path | None = None

    def evaluate(self, report: Report) -> list[str]:
        policy = FindingPolicy(
            max_critical=self.max_critical,
            max_high=self.max_high,
            max_medium=self.max_medium,
            max_low=self.max_low,
            fail_on_new=self.fail_on_new,
            baseline_report=self.baseline_report,
        )
        return list(_CORE.evaluate_policy(report, policy))


def load_suppressions(path: Path | None):
    """Compatibility wrapper. FindingCore owns suppression loading/validation."""
    return _CORE.load_suppressions(path)


def apply_suppressions(report: Report, suppressions: list[Suppression]) -> Report:
    """Compatibility wrapper. FindingCore owns suppression decisions."""
    return _CORE.apply_suppressions(report, suppressions)[0]
