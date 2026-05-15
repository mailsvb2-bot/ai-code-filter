from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .finding_core import FindingCore
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class BehaviorProbeResult:
    name: str
    probe_type: str
    target: str
    ok: bool
    duration_seconds: float | None
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.probe_type,
            "target": self.target,
            "ok": self.ok,
            "duration_seconds": self.duration_seconds,
            "details": self.details,
        }


@dataclass(frozen=True)
class BehaviorAuditSummary:
    probes: tuple[BehaviorProbeResult, ...]

    def to_dict(self) -> dict[str, Any]:
        passed = sum(1 for probe in self.probes if probe.ok)
        return {
            "total": len(self.probes),
            "passed": passed,
            "failed": len(self.probes) - passed,
            "probes": [probe.to_dict() for probe in self.probes],
        }


def audit_behavior(
    project: str | Path,
    *,
    spec: str | Path | None = None,
    timeout: int = 10,
    import_smoke: bool = False,
    max_imports: int = 50,
    deny_network: bool = False,
    allow_commands: bool = True,
    env_allowlist: tuple[str, ...] = (),
    deny_secret_env: bool = False,
) -> tuple[Report, BehaviorAuditSummary]:
    """Execute explicit behavior contracts against production code.

    This is not a replacement for a complete integration test suite. It is a
    deterministic CI helper that runs reviewable probes in subprocesses with
    timeouts and turns mismatches into normal FindingCore issues.
    """
    root = Path(project).resolve()
    report = Report()
    probes = _load_spec_probes(spec) if spec else []
    if import_smoke:
        probes.extend(_build_import_smoke_probes(root, max_imports=max_imports))
    if not probes:
        report.add(Issue(
            file=str(root),
            category="BEHAVIOR001: no behavior probes configured",
            severity=Severity.HIGH,
            detector="behavior_audit",
            description="No behavior contract spec or import-smoke probes were provided, so production behavior was not executed.",
            recommendation="Add a behavior contract JSON file or run with --import-smoke for a minimal import-level smoke check.",
            confidence="high",
            evidence={"spec": str(spec) if spec else None, "import_smoke": import_smoke},
        ))
        core_result = FindingCore().process(report)
        return core_result.report, BehaviorAuditSummary(())
    results: list[BehaviorProbeResult] = []
    for index, probe in enumerate(probes, start=1):
        result = _run_probe(root, probe, default_timeout=timeout, index=index, deny_network=deny_network, allow_commands=allow_commands, env_allowlist=env_allowlist, deny_secret_env=deny_secret_env)
        results.append(result)
        if not result.ok:
            report.add(_issue_from_probe_result(root, probe, result, index=index))
    core_result = FindingCore().process(report)
    return core_result.report, BehaviorAuditSummary(tuple(results))


def write_behavior_summary(path: str | Path | None, summary: BehaviorAuditSummary, report: Report) -> None:
    """Write behavior summary JSON when a path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "behavior": summary.to_dict(),
        "audit_summary": report.summary(),
        "issues": [issue.to_dict() for issue in report.issues],
    }
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_spec_probes(spec: str | Path | None) -> list[dict[str, Any]]:
    if not spec:
        return []
    path = Path(spec)
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        probes = data
    else:
        probes = data.get("probes") or data.get("contracts") or []
    if not isinstance(probes, list):
        raise ValueError("behavior spec must contain a list under 'probes' or 'contracts'")
    return [probe for probe in probes if isinstance(probe, dict)]


def _build_import_smoke_probes(root: Path, *, max_imports: int) -> list[dict[str, Any]]:
    modules: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if _is_ignored(path) or _is_test_path(path, root):
            continue
        if path.name == "__init__.py":
            continue
        module = _module_name(path, root)
        if not module or module.endswith(".__main__"):
            continue
        modules.append(module)
        if len(modules) >= max_imports:
            break
    return [{"name": f"import {module}", "type": "import", "target": module} for module in modules]


def _run_probe(root: Path, probe: dict[str, Any], *, default_timeout: int, index: int, deny_network: bool = False, allow_commands: bool = True, env_allowlist: tuple[str, ...] = (), deny_secret_env: bool = False) -> BehaviorProbeResult:
    import time

    probe_type = str(probe.get("type") or "").strip().lower()
    name = str(probe.get("name") or f"probe-{index}")
    target = str(probe.get("target") or probe.get("module") or probe.get("cmd") or "")
    timeout = int(probe.get("timeout") or default_timeout)
    started = time.monotonic()
    try:
        if probe_type == "import":
            completed = _run_python_probe(root, {"kind": "import", "target": target}, timeout=timeout, deny_network=deny_network, env_allowlist=env_allowlist, deny_secret_env=deny_secret_env)
            result = _evaluate_import_result(completed)
        elif probe_type == "function":
            completed = _run_python_probe(root, {"kind": "function", "probe": probe}, timeout=timeout, deny_network=deny_network, env_allowlist=env_allowlist, deny_secret_env=deny_secret_env)
            result = _evaluate_function_result(completed, probe)
        elif probe_type == "command":
            if not allow_commands:
                return BehaviorProbeResult(name, probe_type, target, False, None, {"error": "command probes disabled by sandbox policy"})
            completed = _run_command_probe(root, probe, timeout=timeout, deny_network=deny_network, env_allowlist=env_allowlist, deny_secret_env=deny_secret_env)
            result = _evaluate_command_result(completed, probe)
        else:
            return BehaviorProbeResult(name, probe_type or "unknown", target, False, None, {"error": f"unsupported probe type: {probe_type!r}"})
        duration = round(time.monotonic() - started, 3)
        return BehaviorProbeResult(name, probe_type, target, result["ok"], duration, result)
    except subprocess.TimeoutExpired as exc:
        duration = round(time.monotonic() - started, 3)
        return BehaviorProbeResult(name, probe_type or "unknown", target, False, duration, {
            "error": "timeout",
            "timeout": timeout,
            "stdout_tail": _tail(_as_text(exc.stdout)),
            "stderr_tail": _tail(_as_text(exc.stderr)),
        })
    except Exception as exc:
        duration = round(time.monotonic() - started, 3)
        return BehaviorProbeResult(name, probe_type or "unknown", target, False, duration, {"error": f"{type(exc).__name__}: {exc}"})


def _run_python_probe(root: Path, payload: dict[str, Any], *, timeout: int, deny_network: bool = False, env_allowlist: tuple[str, ...] = (), deny_secret_env: bool = False) -> subprocess.CompletedProcess[str]:
    script = r'''
import importlib
import io
import json
import traceback
from contextlib import redirect_stderr, redirect_stdout

payload = json.loads(__PAYLOAD__)
if payload.get("deny_network"):
    import socket
    def _blocked_socket(*args, **kwargs):
        raise RuntimeError("network disabled by behavior-audit sandbox")
    socket.socket = _blocked_socket
out = io.StringIO()
err = io.StringIO()
result = {"ok": False, "kind": payload.get("kind")}
try:
    with redirect_stdout(out), redirect_stderr(err):
        if payload.get("kind") == "import":
            importlib.import_module(payload["target"])
            result.update({"ok": True, "result": None})
        elif payload.get("kind") == "function":
            probe = payload["probe"]
            target = probe["target"]
            module_name, _, attr_path = target.partition(":")
            if not module_name or not attr_path:
                raise ValueError("function target must be 'module:callable'")
            obj = importlib.import_module(module_name)
            for part in attr_path.split("."):
                obj = getattr(obj, part)
            args = probe.get("args", [])
            kwargs = probe.get("kwargs", {})
            value = obj(*args, **kwargs)
            result.update({"ok": True, "result": value})
except Exception as exc:
    result.update({
        "ok": False,
        "exception_type": type(exc).__name__,
        "exception_message": str(exc),
        "traceback_tail": traceback.format_exc()[-4000:],
    })
finally:
    result["stdout"] = out.getvalue()
    result["stderr"] = err.getvalue()
print(json.dumps(result, ensure_ascii=False, default=repr))
'''.replace("__PAYLOAD__", repr(json.dumps({**payload, "deny_network": deny_network}, ensure_ascii=False)))
    return subprocess.run(
        (sys.executable, "-c", script),
        cwd=str(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=_probe_env(root, deny_network=deny_network, env_allowlist=env_allowlist, deny_secret_env=deny_secret_env),
    )


def _run_command_probe(root: Path, probe: dict[str, Any], *, timeout: int, deny_network: bool = False, env_allowlist: tuple[str, ...] = (), deny_secret_env: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = probe.get("cmd") or probe.get("command")
    if isinstance(cmd, str):
        command = cmd.split()
    elif isinstance(cmd, list) and all(isinstance(part, str) for part in cmd):
        command = cmd
    else:
        raise ValueError("command probe requires cmd as a string or list of strings")
    return subprocess.run(
        tuple(command),
        cwd=str(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=_probe_env(root, deny_network=deny_network, env_allowlist=env_allowlist, deny_secret_env=deny_secret_env),
    )


def _evaluate_import_result(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    parsed = _parse_probe_json(completed)
    ok = completed.returncode == 0 and bool(parsed.get("ok"))
    return {
        "ok": ok,
        "returncode": completed.returncode,
        "stdout_tail": _tail(completed.stdout),
        "stderr_tail": _tail(completed.stderr),
        "probe_result": parsed,
    }


def _evaluate_function_result(completed: subprocess.CompletedProcess[str], probe: dict[str, Any]) -> dict[str, Any]:
    parsed = _parse_probe_json(completed)
    expect = probe.get("expect") or {}
    ok, reason = _expectation_matches(parsed, expect)
    return {
        "ok": completed.returncode == 0 and ok,
        "reason": reason,
        "returncode": completed.returncode,
        "stdout_tail": _tail(completed.stdout),
        "stderr_tail": _tail(completed.stderr),
        "probe_result": parsed,
        "expect": expect,
    }


def _evaluate_command_result(completed: subprocess.CompletedProcess[str], probe: dict[str, Any]) -> dict[str, Any]:
    expect = probe.get("expect") or {}
    expected_exit = int(expect.get("exit_code", 0))
    checks: list[tuple[bool, str]] = [(completed.returncode == expected_exit, f"exit_code={completed.returncode}, expected={expected_exit}")]
    if "stdout_contains" in expect:
        checks.append((str(expect["stdout_contains"]) in completed.stdout, "stdout_contains"))
    if "stderr_contains" in expect:
        checks.append((str(expect["stderr_contains"]) in completed.stderr, "stderr_contains"))
    if "stdout_not_contains" in expect:
        checks.append((str(expect["stdout_not_contains"]) not in completed.stdout, "stdout_not_contains"))
    ok = all(check for check, _ in checks)
    return {
        "ok": ok,
        "checks": [{"ok": check, "name": name} for check, name in checks],
        "returncode": completed.returncode,
        "stdout_tail": _tail(completed.stdout),
        "stderr_tail": _tail(completed.stderr),
        "expect": expect,
    }


def _expectation_matches(parsed: dict[str, Any], expect: dict[str, Any]) -> tuple[bool, str]:
    if "raises" in expect:
        expected = str(expect["raises"])
        actual = str(parsed.get("exception_type") or "")
        return (actual == expected, f"raises={actual!r}, expected={expected!r}")
    if not parsed.get("ok"):
        return False, f"unexpected exception: {parsed.get('exception_type')}: {parsed.get('exception_message')}"
    value = parsed.get("result")
    if "equals" in expect:
        return (value == expect["equals"], f"equals={value!r}, expected={expect['equals']!r}")
    if "contains" in expect:
        return (str(expect["contains"]) in str(value), "contains")
    if "type" in expect:
        return (type(value).__name__ == str(expect["type"]), f"type={type(value).__name__}, expected={expect['type']}")
    if "truthy" in expect:
        return (bool(value) is bool(expect["truthy"]), f"truthy={bool(value)}, expected={bool(expect['truthy'])}")
    return True, "no explicit expectation; call completed"


def _parse_probe_json(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    text = completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else "{}"
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {"raw": parsed}
    except json.JSONDecodeError:
        return {"ok": False, "parse_error": "probe did not emit JSON", "stdout_tail": _tail(completed.stdout), "stderr_tail": _tail(completed.stderr)}


def _issue_from_probe_result(root: Path, probe: dict[str, Any], result: BehaviorProbeResult, *, index: int) -> Issue:
    severity = Severity.CRITICAL if result.details.get("error") == "timeout" else Severity.HIGH
    return Issue(
        file=str(root),
        category="BEHAVIOR010: behavior probe failed",
        severity=severity,
        detector="behavior_audit",
        description=f"Behavior probe {result.name!r} did not satisfy its contract.",
        recommendation="Fix production behavior or update the explicit behavior contract if the expected behavior intentionally changed.",
        location=f"probe:{index}",
        confidence="high",
        evidence={"probe": probe, "result": result.to_dict()},
    )


def _probe_env(root: Path, deny_network: bool = False, env_allowlist: tuple[str, ...] = (), deny_secret_env: bool = False) -> dict[str, str]:
    base_keys = {"PATH", "SYSTEMROOT", "WINDIR", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL"}
    allowed = set(base_keys) | {str(item) for item in env_allowlist}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    if not env_allowlist and not deny_secret_env:
        # Backwards-compatible mode: preserve current environment unless stricter sandbox flags are requested.
        env = os.environ.copy()
    if deny_secret_env:
        secret_pattern = ("SECRET", "TOKEN", "PASSWORD", "KEY", "CREDENTIAL")
        env = {key: value for key, value in env.items() if not any(marker in key.upper() for marker in secret_pattern)}
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(root) if not existing else f"{root}{os.pathsep}{existing}"
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    if deny_network:
        env["AI_CODE_FILTER_NETWORK_DISABLED"] = "1"
    return env


def _is_test_path(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        rel_parts = path.parts
    return "tests" in rel_parts or path.name.startswith("test_") or path.name.endswith("_test.py")


def _module_name(path: Path, root: Path) -> str:
    rel = path.resolve().relative_to(root.resolve()).with_suffix("")
    parts = [part for part in rel.parts if part != "__init__"]
    return ".".join(parts)


def _is_ignored(path: Path) -> bool:
    ignored = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}
    return any(part in ignored for part in path.parts)


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _tail(text: str, *, max_chars: int = 5000) -> str:
    return text[-max_chars:] if len(text) > max_chars else text
