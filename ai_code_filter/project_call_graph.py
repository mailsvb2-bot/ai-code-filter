from __future__ import annotations

import ast
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .filesystem import collect_files, infer_project_root, validate_text_file
from .models import FilePayload, Issue, Report, Severity
from .symbols import SymbolTable, call_name, build_symbol_table


@dataclass(frozen=True)
class CallGraphNode:
    id: str
    kind: str
    file: str
    line: int | None = None
    parameters: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()


@dataclass(frozen=True)
class CallGraphEdge:
    caller: str
    callee: str
    raw_call: str
    file: str
    line: int | None
    confidence: str = "medium"
    kind: str = "direct"
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UnknownCall:
    caller: str
    raw_call: str
    file: str
    line: int | None
    reason: str


@dataclass
class ProjectCallGraph:
    project_root: str
    nodes: dict[str, CallGraphNode] = field(default_factory=dict)
    edges: list[CallGraphEdge] = field(default_factory=list)
    unknown_calls: list[UnknownCall] = field(default_factory=list)
    module_exports: dict[str, str] = field(default_factory=dict)
    import_aliases: dict[str, dict[str, str]] = field(default_factory=dict)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_root": self.project_root,
            "summary": self.summary(),
            "nodes": [asdict(node) for node in sorted(self.nodes.values(), key=lambda n: n.id)],
            "edges": [asdict(edge) for edge in self.edges],
            "unknown_calls": [asdict(call) for call in self.unknown_calls],
            "module_exports": dict(sorted(self.module_exports.items())),
            "import_aliases": {k: dict(sorted(v.items())) for k, v in sorted(self.import_aliases.items())},
            "limitations": {
                "dynamic_dispatch": "reported as unknown/low-confidence when getattr/importlib/container/runtime DI is detected",
                "type_inference": "constructor assignments, simple factories, and return annotations only",
                "control_flow": "call graph records call sites but does not prove branch feasibility",
                "depth": "path rendering is bounded by the requested max_depth",
            },
        }

    def summary(self) -> dict[str, Any]:
        total_calls = len(self.edges) + len(self.unknown_calls)
        unknown_ratio = (len(self.unknown_calls) / total_calls) if total_calls else 0.0
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "unknown_calls": len(self.unknown_calls),
            "unknown_call_ratio": round(unknown_ratio, 4),
            "truncated": self.truncated,
        }

    def find_paths_to(self, sink_predicate, *, max_depth: int = 4) -> list[list[CallGraphEdge]]:
        outgoing: dict[str, list[CallGraphEdge]] = {}
        for edge in self.edges:
            outgoing.setdefault(edge.caller, []).append(edge)
        paths: list[list[CallGraphEdge]] = []
        for start in sorted(self.nodes):
            stack: list[tuple[str, list[CallGraphEdge], set[str]]] = [(start, [], {start})]
            while stack:
                node, path, seen = stack.pop()
                if len(path) >= max_depth:
                    continue
                for edge in outgoing.get(node, []):
                    new_path = [*path, edge]
                    if sink_predicate(edge.callee):
                        paths.append(new_path)
                    if edge.callee in seen:
                        continue
                    if edge.callee in outgoing:
                        stack.append((edge.callee, new_path, {*seen, edge.callee}))
        return paths


def build_project_call_graph(paths: list[str], *, extensions: Iterable[str] | None = None, max_files: int = 10000) -> ProjectCallGraph:
    root = infer_project_root(paths)
    exts = tuple(extensions or (".py",))
    files = [path for path in collect_files(paths, exts) if path.suffix == ".py"]
    graph = ProjectCallGraph(project_root=str(root))
    if len(files) > max_files:
        files = files[:max_files]
        graph.truncated = True
    payloads: list[FilePayload] = []
    for path in files:
        try:
            payloads.append(FilePayload(path=path, project_root=root, content=validate_text_file(path)))
        except Exception:
            continue
    builder = _CallGraphBuilder(graph, payloads)
    builder.build()
    return graph


def write_call_graph(graph: ProjectCallGraph, output: str | None) -> Path | None:
    """Write graph JSON and return the output path, or None when output is disabled."""
    if not output:
        return None
    path = Path(output)
    path.write_text(json.dumps(graph.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def audit_call_graph(graph: ProjectCallGraph, *, max_unknown_ratio: float | None = None) -> Report:
    report = Report()
    if max_unknown_ratio is not None and graph.summary()["unknown_call_ratio"] > max_unknown_ratio:
        report.add(Issue(
            file="<call-graph>",
            category="CALLGRAPH001: Unknown call ratio exceeds budget",
            severity=Severity.HIGH,
            detector="call_graph",
            description=f"Unknown/dynamic calls ratio is {graph.summary()['unknown_call_ratio']}, over budget {max_unknown_ratio}.",
            recommendation="Reduce dynamic dispatch, add type annotations, or increase the budget explicitly after review.",
            confidence="high",
            evidence={"summary": graph.summary()},
        ))
    for unknown in graph.unknown_calls:
        if unknown.reason in {"getattr", "importlib", "dynamic-call-result"}:
            report.add(Issue(
                file=unknown.file,
                category="CALLGRAPH002: Dynamic call requires review",
                severity=Severity.LOW,
                detector="call_graph",
                description=f"Dynamic call in {unknown.caller}: {unknown.raw_call}.",
                recommendation="Prefer explicit call targets or document/suppress intentionally dynamic dispatch.",
                line_number=unknown.line,
                location=unknown.raw_call,
                confidence="medium",
                evidence=asdict(unknown),
            ))
    return report


class _CallGraphBuilder:
    def __init__(self, graph: ProjectCallGraph, payloads: list[FilePayload]) -> None:
        self.graph = graph
        self.payloads = payloads
        self.trees: dict[str, ast.AST] = {}
        self.symbols: dict[str, SymbolTable] = {}
        self.module_by_file: dict[str, str] = {}
        self.object_types: dict[str, dict[str, str]] = {}
        self.function_returns: dict[str, str] = {}

    def build(self) -> None:
        for payload in self.payloads:
            try:
                tree = ast.parse(payload.content)
            except SyntaxError:
                continue
            module = _module_name(payload.path, payload.project_root)
            rel = payload.relative_path
            self.trees[rel] = tree
            self.module_by_file[rel] = module
            self.symbols[rel] = build_symbol_table(tree)
            imports = _build_import_map(tree, module)
            self.graph.import_aliases[module] = imports
            self._index_nodes(tree, module, rel)
            self._index_reexports(tree, module)
        self._index_return_types()
        for payload in self.payloads:
            rel = payload.relative_path
            tree = self.trees.get(rel)
            if tree is None:
                continue
            self._index_object_types(tree, rel)
        for payload in self.payloads:
            rel = payload.relative_path
            tree = self.trees.get(rel)
            if tree is None:
                continue
            self._index_edges(tree, self.module_by_file[rel], rel)

    def _index_nodes(self, tree: ast.AST, module: str, file: str) -> None:
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qn = f"{module}.{node.name}"
                self.graph.nodes[qn] = CallGraphNode(qn, "function", file, node.lineno, _params(node), _decorators(node))
                self.graph.module_exports.setdefault(node.name, qn)
                self.graph.module_exports[f"{module}.{node.name}"] = qn
            elif isinstance(node, ast.ClassDef):
                class_id = f"{module}.{node.name}"
                self.graph.nodes[class_id] = CallGraphNode(class_id, "class", file, node.lineno, decorators=_decorators(node))
                self.graph.module_exports.setdefault(node.name, class_id)
                self.graph.module_exports[class_id] = class_id
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        raw_params = _params(child)
                        params = raw_params[1:] if raw_params and raw_params[0] in {"self", "cls"} else raw_params
                        qn = f"{class_id}.{child.name}"
                        self.graph.nodes[qn] = CallGraphNode(qn, "method", file, child.lineno, params, _decorators(child))
                        self.graph.module_exports[f"{node.name}.{child.name}"] = qn
                        self.graph.module_exports[qn] = qn

    def _index_reexports(self, tree: ast.AST, module: str) -> None:
        imports = self.graph.import_aliases.get(module, {})
        for node in tree.body if isinstance(tree, ast.Module) else []:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                target = imports.get(node.value.id)
                if not target:
                    continue
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.graph.module_exports[f"{module}.{t.id}"] = target
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    target = imports.get(local)
                    if target:
                        self.graph.module_exports[f"{module}.{local}"] = target

    def _index_return_types(self) -> None:
        for rel, tree in self.trees.items():
            module = self.module_by_file[rel]
            imports = self.graph.import_aliases.get(module, {})
            symbols = self.symbols[rel]
            for owner, fn in _iter_functions_with_owner(tree, module):
                qn = f"{owner}.{fn.name}" if owner else f"{module}.{fn.name}"
                if fn.returns:
                    target = _annotation_name(fn.returns)
                    if target:
                        self.function_returns[qn] = _resolve_external_name(target, imports, symbols)
                        continue
                for ret in [n for n in ast.walk(fn) if isinstance(n, ast.Return) and isinstance(n.value, ast.Call)]:
                    target = self._resolve_call_target(ret.value.func, module, rel, local_objects={})
                    if target and target.split(".")[-1][:1].isupper():
                        self.function_returns[qn] = target
                        break

    def _index_object_types(self, tree: ast.AST, rel: str) -> None:
        module = self.module_by_file[rel]
        objects: dict[str, str] = {}
        for fn_owner, fn in _iter_functions_with_owner(tree, module):
            scope = f"{fn_owner}.{fn.name}" if fn_owner else f"{module}.{fn.name}"
            local_objects: dict[str, str] = {}
            for node in ast.walk(fn):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    if value is None:
                        continue
                    target_type = None
                    if isinstance(value, ast.Call):
                        target_type = self._resolve_call_target(value.func, module, rel, local_objects)
                        if target_type in self.function_returns:
                            target_type = self.function_returns[target_type]
                    if not target_type and isinstance(node, ast.AnnAssign) and node.annotation is not None:
                        ann = _annotation_name(node.annotation)
                        if ann:
                            target_type = _resolve_external_name(ann, self.graph.import_aliases.get(module, {}), self.symbols[rel])
                    if target_type and _looks_like_type(target_type):
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            for name in _target_names(target):
                                local_objects[name] = target_type
                                objects[f"{scope}:{name}"] = target_type
            self.object_types[scope] = local_objects
        self.object_types[rel] = objects

    def _index_edges(self, tree: ast.AST, module: str, rel: str) -> None:
        for owner, fn in _iter_functions_with_owner(tree, module):
            caller = f"{owner}.{fn.name}" if owner else f"{module}.{fn.name}"
            local_objects = self.object_types.get(caller, {})
            for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
                self._record_call(caller, call, module, rel, local_objects)

    def _record_call(self, caller: str, call: ast.Call, module: str, rel: str, local_objects: dict[str, str]) -> None:
        raw = call_name(call.func) or (ast.unparse(call.func) if hasattr(ast, "unparse") else "<dynamic>")
        if isinstance(call.func, ast.Call):
            self.graph.unknown_calls.append(UnknownCall(caller, raw, rel, getattr(call, "lineno", None), _dynamic_reason(call.func)))
            return
        target = self._resolve_call_target(call.func, module, rel, local_objects)
        if not target:
            self.graph.unknown_calls.append(UnknownCall(caller, raw, rel, getattr(call, "lineno", None), _dynamic_reason(call.func)))
            return
        confidence = "high" if target in self.graph.nodes or target in self.graph.module_exports.values() else "medium"
        if raw.startswith("getattr") or target.endswith(".<dynamic>"):
            confidence = "low"
        self.graph.edges.append(CallGraphEdge(
            caller=caller,
            callee=target,
            raw_call=raw,
            file=rel,
            line=getattr(call, "lineno", None),
            confidence=confidence,
            kind="internal" if target in self.graph.nodes else "external",
            evidence={"raw_call": raw, "canonical_call": target, "callsite": ast.unparse(call) if hasattr(ast, "unparse") else None},
        ))

    def _resolve_call_target(self, func: ast.AST, module: str, rel: str, local_objects: dict[str, str]) -> str | None:
        raw = call_name(func)
        if not raw:
            return None
        imports = self.graph.import_aliases.get(module, {})
        symbols = self.symbols[rel]
        if "." in raw:
            first, rest = raw.split(".", 1)
            if first in local_objects:
                candidate = f"{local_objects[first]}.{rest}"
                return self.graph.module_exports.get(candidate, candidate)
            if first in imports:
                candidate = f"{imports[first]}.{rest}"
                return self.graph.module_exports.get(candidate, candidate)
        if raw in imports:
            return self.graph.module_exports.get(imports[raw], imports[raw])
        canonical = symbols.resolve_name(func).canonical or raw
        if canonical in self.graph.module_exports:
            return self.graph.module_exports[canonical]
        if f"{module}.{canonical}" in self.graph.module_exports:
            return self.graph.module_exports[f"{module}.{canonical}"]
        if canonical in self.graph.nodes:
            return canonical
        if raw in self.graph.module_exports:
            return self.graph.module_exports[raw]
        return canonical


def _module_name(path: Path, root: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        rel = Path(path.stem)
    parts = [part for part in rel.parts if part != "__init__"]
    return ".".join(parts) if parts else path.stem


def _build_import_map(tree: ast.AST, current_module: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    package_parts = current_module.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                mapping[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None and not node.level:
                continue
            base = node.module or ""
            if node.level:
                keep = max(0, len(package_parts) - node.level + 1)
                prefix = ".".join(package_parts[:keep])
                base = f"{prefix}.{base}" if prefix and base else prefix or base
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                mapping[local] = f"{base}.{alias.name}" if base else alias.name
    return mapping


def _iter_functions_with_owner(tree: ast.AST, module: str):
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield None, node
        elif isinstance(node, ast.ClassDef):
            owner = f"{module}.{node.name}"
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield owner, child


def _params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    return tuple(arg.arg for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs])


def _decorators(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> tuple[str, ...]:
    return tuple(call_name(dec) or (ast.unparse(dec) if hasattr(ast, "unparse") else "<dynamic>") for dec in node.decorator_list)


def _annotation_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return call_name(node)
    if isinstance(node, ast.Subscript):
        return call_name(node.value)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _resolve_external_name(raw: str, imports: dict[str, str], symbols: SymbolTable) -> str:
    root, sep, rest = raw.partition(".")
    if root in imports:
        return f"{imports[root]}.{rest}" if sep else imports[root]
    return raw


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in target.elts:
            out.extend(_target_names(elt))
        return out
    return []


def _looks_like_type(name: str) -> bool:
    leaf = name.rsplit(".", 1)[-1]
    return bool(leaf and leaf[:1].isupper())


def _dynamic_reason(func: ast.AST) -> str:
    raw = call_name(func) or ""
    if raw.startswith("getattr"):
        return "getattr"
    if raw.startswith("importlib"):
        return "importlib"
    if isinstance(func, ast.Call):
        return "dynamic-call-result"
    return "unresolved"
