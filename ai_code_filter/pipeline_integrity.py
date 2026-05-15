from __future__ import annotations

import ast
from pathlib import Path

from .models import Issue, Severity


def validate_pipeline_integrity(project_root: Path) -> list[Issue]:
    """Verify that the package still wires mandatory lifecycle calls.

    This is intentionally deterministic and local. It checks the source of the
    pipeline before analysis so a future refactor cannot silently remove drift
    recording or core analyzer wiring.
    """
    pipeline_path = project_root / "ai_code_filter" / "pipeline.py"
    if not pipeline_path.exists():
        return [Issue(file="ai_code_filter/pipeline.py", category="Pipeline integrity", severity=Severity.CRITICAL, detector="pipeline_integrity", description="pipeline.py is missing.", recommendation="Restore the canonical AnalysisPipeline module.")]
    try:
        tree = ast.parse(pipeline_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [Issue(file="ai_code_filter/pipeline.py", category="Pipeline integrity", severity=Severity.CRITICAL, detector="pipeline_integrity", description=f"Pipeline source cannot be parsed: {exc}", recommendation="Fix pipeline syntax before running analysis.")]
    analyze_paths = next((node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "analyze_paths"), None)
    if analyze_paths is None:
        return [Issue(file="ai_code_filter/pipeline.py", category="Pipeline integrity", severity=Severity.CRITICAL, detector="pipeline_integrity", description="AnalysisPipeline.analyze_paths is missing.", recommendation="Restore the canonical analysis entrypoint.")]
    called = set()
    for call in ast.walk(analyze_paths):
        if isinstance(call, ast.Call):
            if isinstance(call.func, ast.Name):
                called.add(call.func.id)
            elif isinstance(call.func, ast.Attribute):
                called.add(call.func.attr)
    issues: list[Issue] = []
    if "record_drift" not in called:
        issues.append(Issue(file="ai_code_filter/pipeline.py", category="Pipeline integrity", severity=Severity.CRITICAL, detector="pipeline_integrity", description="record_drift is not called by analyze_paths.", recommendation="Wire drift recording into the main analysis path."))
    if "_run_local_analyzers" not in called:
        issues.append(Issue(file="ai_code_filter/pipeline.py", category="Pipeline integrity", severity=Severity.HIGH, detector="pipeline_integrity", description="Local analyzer execution is not called by analyze_paths.", recommendation="Restore deterministic analyzer execution."))
    return issues
