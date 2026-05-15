from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Issue, Report, Severity

@dataclass(frozen=True)
class DockerSandboxSummary:
    docker_available: bool
    image: str
    command: list[str]
    mounted_project: str
    dry_run: bool
    def to_dict(self) -> dict[str, Any]:
        return {"docker_available": self.docker_available, "image": self.image, "command": self.command, "mounted_project": self.mounted_project, "dry_run": self.dry_run}

def build_behavior_sandbox_command(project: str | Path, *, image: str = "python:3.12-slim", timeout: int = 30, dry_run: bool = True) -> tuple[Report, DockerSandboxSummary]:
    docker = shutil.which("docker") is not None
    project_path = str(Path(project).resolve())
    cmd = ["docker", "run", "--rm", "--network", "none", "--cpus", "1", "--memory", "512m", "--pids-limit", "256", "--read-only", "-v", f"{project_path}:/workspace:ro", "-w", "/workspace", image, "python", "ai_filter.py", "behavior-audit", "/workspace", "--strict-sandbox", "--timeout", str(timeout), "--ci"]
    report = Report()
    if not docker:
        report.record_skip("<docker>", "docker executable not available; sandbox command generated only")
    if not dry_run:
        report.add(Issue(file="<docker-sandbox>", category="DOCKERBOX001: execution not implemented in safe CLI", severity=Severity.LOW, detector="docker_sandbox", description="This command builds a deterministic Docker sandbox invocation but does not execute Docker itself.", recommendation="Run the emitted command in CI where Docker permissions are explicit.", confidence="high"))
    return report, DockerSandboxSummary(docker, image, cmd, project_path, dry_run)

def write_docker_sandbox_summary(path: str | Path | None, summary: DockerSandboxSummary) -> None:
    if path:
        Path(path).write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
