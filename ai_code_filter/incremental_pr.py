from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .changed_files_audit import audit_changed_files
from .project_call_graph import build_project_call_graph
from .models import Issue, Report, Severity

@dataclass(frozen=True)
class IncrementalPrSummary:
    changed_files: int
    neighborhood_nodes: int
    neighborhood_edges: int
    radius: int
    def to_dict(self) -> dict[str, Any]:
        return {"changed_files": self.changed_files, "neighborhood_nodes": self.neighborhood_nodes, "neighborhood_edges": self.neighborhood_edges, "radius": self.radius}

def _read_changed(path: str | Path | None, inline: tuple[str, ...]) -> list[str]:
    values = list(inline)
    if path:
        values += [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    return sorted(set(values))

def audit_incremental_pr(project: str | Path, *, changed_files: tuple[str, ...] = (), changed_files_list: str | Path | None = None, radius: int = 1) -> tuple[Report, IncrementalPrSummary]:
    changed = _read_changed(changed_files_list, changed_files)
    report, _changed_summary = audit_changed_files(project, changed_files=tuple(changed), extensions=(".py", ".js", ".ts", ".json", ".yaml", ".yml"))
    graph = build_project_call_graph([str(project)])
    changed_set = set(changed); nodes: set[str] = set()
    for node in graph.nodes.values():
        if node.file in changed_set:
            nodes.add(node.id)
    edges = []; frontier = set(nodes)
    for _ in range(max(0, radius)):
        new: set[str] = set()
        for edge in graph.edges:
            if edge.caller in frontier or edge.callee in frontier:
                edges.append(edge); new.add(edge.caller); new.add(edge.callee)
        frontier = new - nodes; nodes |= new
    if not changed:
        report.add(Issue(file=str(project), category="PRMODE001: no changed files supplied", severity=Severity.LOW, detector="incremental_pr", description="Incremental PR mode received no changed files.", recommendation="Pass --changed-file or --changed-files-list from git diff.", confidence="high"))
    return report, IncrementalPrSummary(len(changed), len(nodes), len(edges), radius)

def write_incremental_pr_summary(path: str | Path | None, summary: IncrementalPrSummary) -> None:
    if path:
        Path(path).write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
