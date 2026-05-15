from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from .config import RuntimeConfig
from .models import Issue, Report, Severity
from .pipeline import AnalysisPipeline


@dataclass(frozen=True)
class PerformanceBudgetResult:
    files: int
    seconds: float
    files_per_second: float
    issues: int

    def to_dict(self) -> dict[str, float | int]:
        return {
            "files": self.files,
            "seconds": round(self.seconds, 6),
            "files_per_second": round(self.files_per_second, 6),
            "issues": self.issues,
        }


def run_performance_budget(*, files: int = 120, max_seconds: float = 8.0, workers: int = 1) -> tuple[Report, PerformanceBudgetResult]:
    """Run a deterministic synthetic-project performance smoke budget.

    This is intentionally a budget smoke test, not a benchmark claim. It verifies that
    the pipeline returns a complete report for a moderately sized generated project and
    fails closed when the runtime budget is exceeded.
    """
    files = max(1, int(files))
    max_seconds = max(0.1, float(max_seconds))
    with TemporaryDirectory(prefix="ai-code-filter-perf-") as tmp:
        root = Path(tmp)
        for idx in range(files):
            (root / f"module_{idx:04d}.py").write_text(
                "def ok(value):\n"
                "    return str(value).strip()\n"
                "\n"
                "def route(request):\n"
                "    q = request.args.get('q')\n"
                "    return ok(q)\n",
                encoding="utf-8",
            )
        config = RuntimeConfig(enable_ai_review=False, enable_drift=False, workers=max(1, workers))
        started = time.perf_counter()
        report = AnalysisPipeline(config).analyze_paths([str(root)])
        elapsed = time.perf_counter() - started
        result = PerformanceBudgetResult(
            files=files,
            seconds=elapsed,
            files_per_second=(files / elapsed) if elapsed > 0 else float("inf"),
            issues=len(report.issues),
        )
        if elapsed > max_seconds:
            report.add(Issue(
                file="<performance-budget>",
                category="performance_budget.exceeded",
                severity=Severity.HIGH,
                detector="performance_budget",
                description=f"Synthetic analysis took {elapsed:.3f}s for {files} files, exceeding {max_seconds:.3f}s budget.",
                recommendation="Profile analyzer ordering, file discovery and per-file parser/cache behavior before enabling this project in strict CI.",
                confidence="high",
                evidence=result.to_dict() | {"max_seconds": max_seconds},
            ))
        return report, result
