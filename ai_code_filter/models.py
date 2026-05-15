from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Issue:
    file: str
    category: str
    severity: Severity = Severity.MEDIUM
    detector: str = "unknown"
    description: str = ""
    recommendation: str = ""
    location: Optional[str] = None
    line_number: Optional[int] = None
    confidence: str = "medium"
    evidence: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class FindingBatch:
    verdict: str
    issues: tuple[Issue, ...]
    summary: str = ""

    @classmethod
    def approved(cls, summary: str = "No problems found.") -> "FindingBatch":
        return cls(verdict="APPROVED", issues=(), summary=summary)


@dataclass(frozen=True)
class FilePayload:
    path: Path
    project_root: Path
    content: str

    @property
    def relative_path(self) -> str:
        try:
            return str(self.path.resolve().relative_to(self.project_root.resolve()))
        except ValueError:
            return str(self.path)


class Report:
    def __init__(self) -> None:
        self._issues: list[Issue] = []
        self.failed_files: list[dict[str, str]] = []
        self.skipped_files: list[dict[str, str]] = []

    @property
    def issues(self) -> tuple[Issue, ...]:
        return tuple(self._issues)

    def add(self, issue: Issue) -> None:
        self._issues.append(issue)

    def extend(self, issues: Iterable[Issue]) -> None:
        self._issues.extend(issues)

    def record_failure(self, file: str, error: Exception) -> None:
        self.failed_files.append({"file": file, "error": f"{type(error).__name__}: {error}"})
        self.add(Issue(
            file=file,
            category="Analyzer failure",
            severity=Severity.HIGH,
            detector="pipeline",
            description="A file was not fully analyzed because an analyzer failed.",
            recommendation="Fix the analyzer failure or exclude the file explicitly.",
        ))

    def record_skip(self, file: str, reason: str) -> None:
        self.skipped_files.append({"file": file, "reason": reason})

    def to_dict(self) -> dict[str, Any]:
        return {
            "issues": [issue.to_dict() for issue in self._issues],
            "failed_files": self.failed_files,
            "skipped_files": self.skipped_files,
            "summary": self.summary(),
            "by_detector": self.by_detector(),
            "by_category": self.by_category(),
        }

    def summary(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for issue in self._issues:
            counts[issue.severity.value] += 1
        counts["TOTAL"] = len(self._issues)
        counts["FAILED_FILES"] = len(self.failed_files)
        counts["SKIPPED_FILES"] = len(self.skipped_files)
        return counts

    def by_detector(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for issue in self._issues:
            counts[issue.detector] = counts.get(issue.detector, 0) + 1
        return dict(sorted(counts.items()))

    def by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for issue in self._issues:
            counts[issue.category] = counts.get(issue.category, 0) + 1
        return dict(sorted(counts.items()))

    def has_blocking_issues(self) -> bool:
        return any(issue.severity in {Severity.CRITICAL, Severity.HIGH} for issue in self._issues) or bool(self.failed_files)
