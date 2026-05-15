from __future__ import annotations

import json
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

from .config import DEFAULT_MODEL, RuntimeConfig
from .finding_core import FindingCore
from .models import Issue, Report, Severity
from .pipeline import AnalysisPipeline
from .project_call_graph import build_project_call_graph


@dataclass(frozen=True)
class StressAuditSummary:
    files: int
    seconds: float
    files_per_second: float
    peak_mb: float
    graph_nodes: int
    graph_edges: int
    unknown_ratio: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "files": self.files,
            "seconds": round(self.seconds, 6),
            "files_per_second": round(self.files_per_second, 3),
            "peak_mb": round(self.peak_mb, 3),
            "graph_nodes": self.graph_nodes,
            "graph_edges": self.graph_edges,
            "unknown_ratio": round(self.unknown_ratio, 6),
        }


def audit_stress(
    *,
    files: int = 500,
    max_seconds: float = 15.0,
    max_peak_mb: float | None = None,
    max_unknown_ratio: float | None = 0.35,
) -> tuple[Report, StressAuditSummary]:
    report = Report()
    files = max(1, int(files))
    with tempfile.TemporaryDirectory(prefix="ai_code_filter_stress_") as td:
        root = Path(td)
        _write_synthetic_project(root, files)
        tracemalloc.start()
        start = time.perf_counter()
        cfg = RuntimeConfig(model=DEFAULT_MODEL, extensions=[".py"], enable_ai_review=False, enable_drift=False, workers=1)
        analysis_report = AnalysisPipeline(cfg).analyze_paths([str(root)])
        graph = build_project_call_graph([str(root)], max_files=files + 10)
        seconds = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        report.failed_files.extend(analysis_report.failed_files)
        if analysis_report.failed_files:
            report.add(Issue(file=str(root), category="STRESS001: analyzer failure during stress run", severity=Severity.HIGH, detector="stress_audit", description="The analyzer failed on the synthetic stress project.", recommendation="Fix the analyzer failure before raising stress budgets.", confidence="high", evidence={"failed_files": analysis_report.failed_files[:20]}))
        summary = StressAuditSummary(
            files=files,
            seconds=seconds,
            files_per_second=files / max(seconds, 1e-9),
            peak_mb=peak / (1024 * 1024),
            graph_nodes=len(graph.nodes),
            graph_edges=len(graph.edges),
            unknown_ratio=float(graph.summary().get("unknown_call_ratio", 0.0)),
        )
        if seconds > max_seconds:
            report.add(Issue(file=str(root), category="STRESS010: performance budget exceeded", severity=Severity.HIGH, detector="stress_audit", description=f"Stress run took {seconds:.3f}s; budget is {max_seconds:.3f}s.", recommendation="Profile expensive analyzers, add incremental mode, or lower per-file overhead.", confidence="high", evidence=summary.to_dict()))
        if max_peak_mb is not None and summary.peak_mb > max_peak_mb:
            report.add(Issue(file=str(root), category="STRESS011: memory budget exceeded", severity=Severity.HIGH, detector="stress_audit", description=f"Peak memory was {summary.peak_mb:.3f} MB; budget is {max_peak_mb:.3f} MB.", recommendation="Reduce graph/payload retention or stream large project analysis.", confidence="medium", evidence=summary.to_dict()))
        if max_unknown_ratio is not None and summary.unknown_ratio > max_unknown_ratio:
            report.add(Issue(file=str(root), category="STRESS020: unknown-call budget exceeded", severity=Severity.MEDIUM, detector="stress_audit", description=f"Unknown call ratio was {summary.unknown_ratio:.3f}; budget is {max_unknown_ratio:.3f}.", recommendation="Improve import/type resolution or exclude intentionally dynamic fixtures.", confidence="medium", evidence=summary.to_dict()))
        return FindingCore().process(report).report, summary


def write_stress_summary(path: str | Path | None, summary: StressAuditSummary, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"stress_audit": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_synthetic_project(root: Path, files: int) -> None:
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    for idx in range(files):
        next_name = f"m{idx + 1}" if idx + 1 < files else "m0"
        text = (
            f"from pkg import {next_name}\n\n"
            f"def f{idx}(value: int) -> int:\n"
            f"    if value > {idx % 7}:\n"
            f"        return {next_name}.f{(idx + 1) % files}(value - 1) if value else value\n"
            f"    return value + {idx}\n"
        )
        (root / "pkg" / f"m{idx}.py").write_text(text, encoding="utf-8")
