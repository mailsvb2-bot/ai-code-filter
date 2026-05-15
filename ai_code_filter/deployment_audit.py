from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity


def audit_deployment(project: str | Path) -> Report:
    root = Path(project).resolve()
    report = Report()
    for dockerfile in _find(root, names={"Dockerfile"}, suffixes=(".Dockerfile",)):
        _audit_dockerfile(root, dockerfile, report)
    for compose in _find(root, names={"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}):
        _audit_compose(root, compose, report)
    for workflow in (root / ".github" / "workflows").glob("*.yml") if (root / ".github" / "workflows").exists() else []:
        _audit_workflow(root, workflow, report)
    for unit in list(root.rglob("*.service")):
        if not _is_ignored(unit):
            _audit_systemd(root, unit, report)
    for conf in list(root.rglob("*.conf")):
        if not _is_ignored(conf) and re.search(r"nginx|sites-|webhook", str(conf), re.IGNORECASE):
            _audit_nginx(root, conf, report)
    return FindingCore().process(report).report


def write_deployment_summary(path: str | Path | None, report: Report) -> None:
    """Write summary JSON when a path is provided; returns None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _audit_dockerfile(root: Path, path: Path, report: Report) -> None:
    text = _read(path)
    rel = _rel(path, root)
    if "HEALTHCHECK" not in text.upper():
        report.add(_issue(rel, "DEPLOY010: Dockerfile lacks HEALTHCHECK", "Dockerfile has no HEALTHCHECK instruction.", "Add a healthcheck that exercises the app readiness endpoint.", "dockerfile"))
    if re.search(r"COPY\s+\.env\b|ADD\s+\.env\b", text, re.IGNORECASE):
        report.add(_issue(rel, "DEPLOY011: Dockerfile copies env secrets", "Dockerfile copies .env into the image.", "Never bake secrets into images; pass env at deploy time.", "dockerfile", Severity.HIGH))
    if re.search(r"USER\s+root\b", text, re.IGNORECASE) or not re.search(r"^\s*USER\s+", text, re.IGNORECASE | re.MULTILINE):
        report.add(_issue(rel, "DEPLOY012: Dockerfile user not hardened", "Dockerfile does not clearly switch to a non-root runtime user.", "Use a dedicated non-root user for runtime containers.", "dockerfile", Severity.MEDIUM))


def _audit_compose(root: Path, path: Path, report: Report) -> None:
    text = _read(path)
    rel = _rel(path, root)
    if re.search(r"POSTGRES_PASSWORD\s*[:=]\s*['\"]?(password|postgres|changeme)", text, re.IGNORECASE):
        report.add(_issue(rel, "DEPLOY020: weak compose database secret", "Compose file contains a weak/default Postgres password.", "Use secrets or deployment-managed environment variables.", "compose", Severity.HIGH))
    if "restart:" not in text:
        report.add(_issue(rel, "DEPLOY021: compose lacks restart policy", "Compose services do not declare a restart policy.", "Set a reviewed restart policy for long-running services.", "compose", Severity.MEDIUM))


def _audit_workflow(root: Path, path: Path, report: Report) -> None:
    text = _read(path)
    rel = _rel(path, root)
    if "pytest" not in text and "ai_filter.py" not in text and "ai-code-filter" not in text:
        report.add(_issue(rel, "DEPLOY030: workflow lacks quality gate", "GitHub Actions workflow does not appear to run tests or ai-code-filter gates.", "Add pytest and release/audit gates before deploy/publish steps.", "github_actions", Severity.MEDIUM))
    if re.search(r"echo\s+\$\{\{\s*secrets\.", text, re.IGNORECASE):
        report.add(_issue(rel, "DEPLOY031: workflow may echo secrets", "Workflow appears to echo GitHub secrets.", "Never echo secrets; pass them only to trusted commands.", "github_actions", Severity.HIGH))


def _audit_systemd(root: Path, path: Path, report: Report) -> None:
    text = _read(path)
    rel = _rel(path, root)
    if "Restart=" not in text:
        report.add(_issue(rel, "DEPLOY040: systemd lacks restart policy", "systemd unit lacks Restart= policy.", "Set Restart=on-failure/always as appropriate.", "systemd", Severity.MEDIUM))
    if "WorkingDirectory=" not in text:
        report.add(_issue(rel, "DEPLOY041: systemd lacks working directory", "systemd unit lacks WorkingDirectory=.", "Set an explicit project WorkingDirectory to avoid path-dependent boot failures.", "systemd", Severity.MEDIUM))
    if re.search(r"Environment=.*TOKEN=|Environment=.*SECRET=", text):
        report.add(_issue(rel, "DEPLOY042: systemd inline secret", "systemd unit appears to inline a token/secret.", "Use EnvironmentFile with protected permissions or a secret manager.", "systemd", Severity.HIGH))


def _audit_nginx(root: Path, path: Path, report: Report) -> None:
    text = _read(path)
    rel = _rel(path, root)
    if "proxy_pass" in text and "proxy_set_header" not in text:
        report.add(_issue(rel, "DEPLOY050: nginx proxy headers missing", "nginx proxy config lacks proxy_set_header directives.", "Forward Host/X-Forwarded-* headers consistently.", "nginx", Severity.MEDIUM))


def _issue(file: str, category: str, description: str, recommendation: str, detector: str, severity: Severity = Severity.MEDIUM) -> Issue:
    return Issue(file=file, category=category, severity=severity, detector=f"deployment_audit.{detector}", description=description, recommendation=recommendation, confidence="medium")


def _find(root: Path, *, names: set[str], suffixes: tuple[str, ...] = ()) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and not _is_ignored(path) and (path.name in names or any(path.name.endswith(s) for s in suffixes)):
            out.append(path)
    return sorted(out)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(errors="replace")


def _is_ignored(path: Path) -> bool:
    ignored = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}
    return any(part in ignored for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
