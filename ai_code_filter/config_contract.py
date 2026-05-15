from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from .models import FilePayload, Issue, Report, Severity

ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
SECRET_NAME_RE = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|private[_-]?key)")
DANGEROUS_DEFAULT_RE = re.compile(r"(?i)(changeme|change-me|secret|password|token|debug|sqlite|localhost|127\.0\.0\.1)")


@dataclass(frozen=True)
class ConfigContractSummary:
    used: set[str]
    documented: set[str]
    secret_defaults: dict[str, str]
    dangerous_defaults: dict[str, str]


def audit_config_contract(project_root: str | Path) -> Report:
    root = Path(project_root)
    report = Report()
    summary = summarize_config_contract(root)
    if not summary.documented:
        return report
    for name in sorted(summary.used - summary.documented):
        report.add(Issue(
            file="<config-contract>",
            category="CFG001: Env var used but undocumented",
            severity=Severity.HIGH,
            detector="config_contract",
            description=f"Environment variable {name} is used in code but absent from .env.example/config examples.",
            recommendation="Document the variable, default semantics, and production requirement in the env contract.",
            confidence="high",
            evidence={"env_var": name, "used": True, "documented": False},
        ))
    for name in sorted(summary.documented - summary.used):
        report.add(Issue(
            file="<config-contract>",
            category="CFG002: Env var documented but unused",
            severity=Severity.LOW,
            detector="config_contract",
            description=f"Environment variable {name} is documented but no direct os.getenv/os.environ usage was found.",
            recommendation="Remove stale config or wire it deliberately.",
            confidence="medium",
            evidence={"env_var": name, "used": False, "documented": True},
        ))
    for name, value in sorted(summary.secret_defaults.items()):
        report.add(Issue(
            file=".env.example",
            category="CFG003: Secret-like default value",
            severity=Severity.HIGH,
            detector="config_contract",
            description=f"Secret-like env var {name} has a non-empty example/default value.",
            recommendation="Use an empty value or placeholder without secret material; never ship usable secrets.",
            confidence="high",
            evidence={"env_var": name, "default_preview": value[:12]},
        ))
    for name, value in sorted(summary.dangerous_defaults.items()):
        report.add(Issue(
            file=".env.example",
            category="CFG004: Dangerous production default",
            severity=Severity.MEDIUM,
            detector="config_contract",
            description=f"Environment variable {name} has a risky default for production-like runs.",
            recommendation="Make production defaults explicit, safe, and fail-closed.",
            confidence="medium",
            evidence={"env_var": name, "default": value},
        ))
    return report


def summarize_config_contract(root: Path) -> ConfigContractSummary:
    used: set[str] = set()
    documented: set[str] = set()
    secret_defaults: dict[str, str] = {}
    dangerous_defaults: dict[str, str] = {}
    for path in root.rglob("*.py"):
        if _skip(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, SyntaxError, OSError):
            continue
        used.update(_env_uses(tree))
    for path in _env_contract_files(root):
        try:
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                name = name.strip().removeprefix("export ").strip()
                value = value.strip().strip('"').strip("'")
                if ENV_KEY_RE.match(name):
                    documented.add(name)
                    if SECRET_NAME_RE.search(name) and value and not value.startswith("<"):
                        secret_defaults[name] = value
                    if DANGEROUS_DEFAULT_RE.search(value) and name.upper() not in {"DEBUG", "ENV", "APP_ENV"}:
                        dangerous_defaults[name] = value
        except OSError:
            continue
    return ConfigContractSummary(used, documented, secret_defaults, dangerous_defaults)


def _env_contract_files(root: Path) -> list[Path]:
    names = {".env.example", ".env.sample", "env.example", "env.sample"}
    return [p for p in root.rglob("*") if p.is_file() and p.name in names and not _skip(p)]


def _env_uses(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call = _call_name(node.func)
        if call in {"os.getenv", "os.environ.get"} and node.args:
            value = node.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and ENV_KEY_RE.match(value.value):
                names.add(value.value)
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and _call_name(node.value) == "os.environ":
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str) and ENV_KEY_RE.match(sl.value):
                names.add(sl.value)
    return names


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _skip(path: Path) -> bool:
    parts = set(path.parts)
    return bool(parts & {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules", "dist", "build"})


class ConfigContractAnalyzer:
    name = "config_contract"

    def __init__(self, payloads: list[FilePayload]) -> None:
        self.project_root = payloads[0].project_root if payloads else Path(".")
        self.anchor = payloads[0].relative_path if payloads else ""
        self._issues: list[Issue] | None = None

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.relative_path != self.anchor:
            return []
        if self._issues is None:
            self._issues = list(audit_config_contract(self.project_root).issues)
        return self._issues
