from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass
from pathlib import Path

from .base import Analyzer
from ..guards.stereotype import estimate_stereotype_score
from ..models import FilePayload, Issue, Severity


@dataclass(frozen=True)
class ChainNode:
    path: Path
    relative_path: str
    module_name: str
    imports: frozenset[str]
    defined_names: frozenset[str]
    calls: tuple[tuple[str, int | None, str], ...]
    stereotype_score: float


def _module_name(payload: FilePayload) -> str:
    try:
        rel = payload.path.resolve().relative_to(payload.project_root.resolve())
    except ValueError:
        rel = payload.path.name
    if isinstance(rel, Path):
        parts = list(rel.with_suffix("").parts)
    else:
        parts = [Path(str(rel)).stem]
    return ".".join(part for part in parts if part != "__init__") or payload.path.stem


def build_chain_nodes(payloads: list[FilePayload]) -> dict[str, ChainNode]:
    nodes: dict[str, ChainNode] = {}
    for payload in payloads:
        if payload.path.suffix != ".py":
            continue
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            continue
        imports: set[str] = set()
        defined: set[str] = set()
        calls: list[tuple[str, int | None, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined.add(target.id)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.append((node.func.id, getattr(node, "lineno", None), ast.unparse(node.func)))
                elif isinstance(node.func, ast.Attribute):
                    calls.append((node.func.attr, getattr(node, "lineno", None), ast.unparse(node.func)))
        name = _module_name(payload)
        aliases = {name, name.split(".")[-1], payload.path.stem}
        chain_node = ChainNode(
            path=payload.path,
            relative_path=payload.relative_path,
            module_name=name,
            imports=frozenset(imports),
            defined_names=frozenset(defined),
            calls=tuple(calls),
            stereotype_score=estimate_stereotype_score(payload.content),
        )
        for alias in aliases:
            nodes[alias] = chain_node
    return nodes


class ChainInspectorAnalyzer(Analyzer):
    name = "chain"

    def __init__(self, nodes: dict[str, ChainNode]) -> None:
        self.nodes = nodes
        self.known_call_names = self._known_call_names()
        self.imported_modules = {name for node in nodes.values() for name in node.imports}

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        node = self.nodes.get(payload.path.stem) or self.nodes.get(_module_name(payload))
        if not node:
            return []
        issues: list[Issue] = []
        if "FORBIDDEN_PATTERNS" not in payload.content and node.stereotype_score > 0.7:
            issues.append(Issue(
                file=payload.relative_path,
                category="Stereotypical code",
                severity=Severity.HIGH,
                detector=self.name,
                description=f"Module has high stereotype index {node.stereotype_score:.2f}.",
                recommendation="Remove flattery, vague review prose and ornamental comments from executable code.",
            ))
        unknown = self._unknown_calls(node)
        if node.calls and len(unknown) / len(node.calls) > 0.55:
            sample = ", ".join(sorted({name for name, _, _ in unknown})[:5])
            issues.append(Issue(
                file=payload.relative_path,
                category="Code hallucinations",
                severity=Severity.HIGH,
                detector=self.name,
                description=f"Unknown call ratio {len(unknown) / len(node.calls):.0%}; sample: {sample}.",
                recommendation="Verify called functions/classes exist or add imports/definitions; ignore external SDK methods via plugin if needed.",
            ))
        return issues

    def dependency_chains(self, max_depth: int = 15) -> list[list[str]]:
        imported = {import_name for node in set(self.nodes.values()) for import_name in node.imports}
        roots = sorted({node.module_name for node in set(self.nodes.values()) if node.module_name.split(".")[-1] not in imported})
        return [self._walk(root, max_depth) for root in roots]

    def _walk(self, root: str, max_depth: int) -> list[str]:
        chain: list[str] = []
        seen: set[str] = set()
        current = root.split(".")[-1]
        for _ in range(max_depth):
            node = self.nodes.get(current)
            if not node or node.module_name in seen:
                break
            chain.append(node.relative_path)
            seen.add(node.module_name)
            next_module = next((imp for imp in sorted(node.imports) if imp in self.nodes), None)
            if not next_module:
                break
            current = next_module
        return chain

    def _known_call_names(self) -> set[str]:
        builtin_names = set(dir(builtins))
        defined = {name for node in set(self.nodes.values()) for name in node.defined_names}
        common_external = {"Path", "ValueError", "RuntimeError", "AssertionError", "Counter", "dataclass", "field", "Enum", "append", "extend", "get", "items", "keys", "values", "read", "write", "read_text", "write_text", "loads", "dumps", "parse", "open", "close", "execute", "fetchone", "fetchall", "create", "format", "join", "strip", "split", "lower", "upper", "replace", "mkdir", "exists", "resolve", "relative_to", "is_file", "is_dir", "startswith", "endswith", "add_argument", "add_parser", "ArgumentParser", "HTMLResponse", "BackgroundTasks", "FastAPI", "Flask", "Django", "module_from_spec", "exec_module", "all", "any", "len", "str", "int", "float", "bool", "isinstance", "getattr", "setattr", "hasattr", "sorted", "sum", "max", "min", "dir", "frozenset", "compile", "findall", "search", "sub", "log2", "abs"}
        return builtin_names | defined | common_external

    def _unknown_calls(self, node: ChainNode) -> list[tuple[str, int | None, str]]:
        return [(name, line, expr) for name, line, expr in node.calls if name not in self.known_call_names]
