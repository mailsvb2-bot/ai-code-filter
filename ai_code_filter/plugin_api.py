from __future__ import annotations

import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import Issue, Severity

class PolicyPack(Protocol):
    name: str
    version: str
    def analyze_text(self, path: str, text: str) -> list[Issue]: ...

@dataclass(frozen=True)
class PluginApiSummary:
    manifest_found: bool
    packs: int
    errors: tuple[str, ...]
    def to_dict(self) -> dict[str, Any]:
        return {"manifest_found": self.manifest_found, "packs": self.packs, "errors": list(self.errors), "api": {"entrypoint": "register_policy_pack()", "methods": ["analyze_text(path, text) -> list[Issue]"], "trusted_only": True}}

def load_policy_pack(path: str | Path) -> tuple[Any | None, str | None]:
    p = Path(path)
    spec = importlib.util.spec_from_file_location(f"ai_code_filter_policy_pack_{p.stem}", p)
    if spec is None or spec.loader is None:
        return None, "cannot create module spec"
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        register = getattr(module, "register_policy_pack", None)
        if register is None:
            return None, "missing register_policy_pack()"
        pack = register()
        if not getattr(pack, "name", None) or not getattr(pack, "version", None) or not callable(getattr(pack, "analyze_text", None)):
            return None, "policy pack must expose name, version and analyze_text(path, text)"
        return pack, None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

def validate_plugin_manifest(project: str | Path) -> tuple[list[Issue], PluginApiSummary]:
    root = Path(project); manifest = root / "policy_packs.json"
    if not manifest.exists():
        return [], PluginApiSummary(False, 0, ())
    errors: list[str] = []; packs = 0
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        return [Issue(file=str(manifest), category="PLUGINAPI001: invalid policy pack manifest", severity=Severity.HIGH, detector="plugin_api", description=str(exc), recommendation="Fix policy_packs.json.", confidence="high")], PluginApiSummary(True, 0, (str(exc),))
    for entry in data.get("packs", []) if isinstance(data, dict) else []:
        _pack, err = load_policy_pack(root / str(entry.get("path", "")))
        if err: errors.append(err)
        else: packs += 1
    issues = [Issue(file=str(manifest), category="PLUGINAPI002: policy pack load error", severity=Severity.HIGH, detector="plugin_api", description=e, recommendation="Fix or remove broken custom policy pack.", confidence="high") for e in errors]
    return issues, PluginApiSummary(True, packs, tuple(errors))
