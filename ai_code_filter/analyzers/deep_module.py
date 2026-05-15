from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .base import Analyzer
from ..models import FilePayload, Issue, Severity


@dataclass(frozen=True)
class ModuleIndex:
    path: Path
    module_name: str
    exported_names: frozenset[str]
    imports: dict[str, str]


def build_module_index(payloads: list[FilePayload]) -> dict[str, ModuleIndex]:
    indexes: dict[str, ModuleIndex] = {}
    for payload in payloads:
        if payload.path.suffix != ".py":
            continue
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            continue
        exports: set[str] = set()
        imports: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                exports.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        exports.add(target.id)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports[node.module.split(".")[0]] = node.module.split(".")[0]
        indexes[payload.path.stem] = ModuleIndex(payload.path, payload.path.stem, frozenset(exports), imports)
    return indexes


class DeepModuleAnalyzer(Analyzer):
    name = "deep_module"

    def __init__(self, module_index: dict[str, ModuleIndex]) -> None:
        self.module_index = module_index

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            return []
        current = self.module_index.get(payload.path.stem)
        if not current:
            return []
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                imported_module = current.imports.get(node.value.id)
                target = self.module_index.get(imported_module or "")
                if target and node.attr not in target.exported_names:
                    issues.append(Issue(file=payload.relative_path, category="Cross-module inconsistency", severity=Severity.HIGH, detector=self.name, description=f"Module uses missing attribute {imported_module}.{node.attr}.", recommendation="Create/export the attribute or fix the call site.", location=ast.unparse(node), line_number=getattr(node, "lineno", None)))
        return issues
