from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from .base import Analyzer
from .python_dataflow import (
    HTML_SINK_NAMES,
    SANITIZER_CALLS,
    SHELL_SINKS,
    SOURCE_ATTRIBUTES,
    SOURCE_CALLS,
    SQL_SINK_SUFFIXES,
    _call_name,
    is_probable_sql_sink,
)
from ..models import FilePayload, Issue, Severity
from ..symbols import SymbolTable, build_symbol_table, evidence_for_call


@dataclass(frozen=True)
class CrossFunctionSummary:
    module: str
    name: str
    qualified_name: str
    params: tuple[str, ...]
    vararg: str | None = None
    kwarg: str | None = None
    default_sources_by_index: dict[int, str] = field(default_factory=dict)
    return_source: str | None = None
    return_param_index: int | None = None
    return_vararg: bool = False
    return_kwarg: bool = False
    sink_kind_by_param: dict[int, str] = field(default_factory=dict)
    sink_uses_vararg: bool = False
    sink_uses_kwarg: bool = False


class PythonCrossFileDataFlowAnalyzer(Analyzer):
    """Cross-file Python data-flow lite.

    It does not claim full program analysis. It builds small summaries for functions exported by
    sibling project modules, then checks whether imported helpers move tainted values into known
    sink wrappers. The implementation is conservative and explainable by design.
    """

    name = "python_cross_file_dataflow"

    def __init__(self, payloads: list[FilePayload]) -> None:
        self.summaries = _build_project_summaries(payloads)

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            return []
        module_name = _module_name(payload.path, payload.project_root)
        import_map = _build_import_map(tree, module_name)
        symbols = build_symbol_table(tree)
        issues: list[Issue] = []
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            issues.extend(_CrossFunctionPass(payload, fn, self.summaries, import_map, symbols).run())
        return _dedupe(issues)


class _CrossFunctionPass:
    def __init__(self, payload: FilePayload, function: ast.FunctionDef | ast.AsyncFunctionDef, summaries: dict[str, CrossFunctionSummary], import_map: dict[str, str], symbols: SymbolTable) -> None:
        self.payload = payload
        self.function = function
        self.summaries = summaries
        self.import_map = import_map
        self.symbols = symbols
        self.tainted: dict[str, str] = {}
        self.object_types: dict[str, str] = {}
        self.issues: list[Issue] = []

    def run(self) -> list[Issue]:
        for stmt in self.function.body:
            self._visit_stmt(stmt)
        return self.issues

    def _visit_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            value = stmt.value
            if value is None:
                return
            self._visit_expr(value)
            source = self._source_for_expr(value)
            object_type = self._constructor_type_for_expr(value)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                for name in _target_names(target):
                    if object_type:
                        self.object_types[name] = object_type
                    elif name in self.object_types and not source:
                        self.object_types.pop(name, None)
                    if source:
                        self.tainted[name] = source
                    elif name in self.tainted:
                        self.tainted.pop(name, None)
        elif isinstance(stmt, ast.Return):
            if stmt.value:
                self._visit_expr(stmt.value)
        elif isinstance(stmt, ast.Expr):
            self._visit_expr(stmt.value)
        elif isinstance(stmt, ast.If):
            self._visit_expr(stmt.test)
            before = dict(self.tainted)
            for child in stmt.body:
                self._visit_stmt(child)
            body_state = dict(self.tainted)
            self.tainted = dict(before)
            for child in stmt.orelse:
                self._visit_stmt(child)
            else_state = dict(self.tainted)
            merged = dict(before)
            merged.update(body_state)
            merged.update(else_state)
            self.tainted = merged
        elif isinstance(stmt, (ast.For, ast.While, ast.Try, ast.With)):
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self._visit_expr(child)
                elif isinstance(child, ast.stmt):
                    self._visit_stmt(child)
                elif isinstance(child, ast.ExceptHandler):
                    for sub in child.body:
                        self._visit_stmt(sub)
        else:
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self._visit_expr(child)

    def _visit_expr(self, expr: ast.expr) -> None:
        if isinstance(expr, ast.Call):
            self._check_cross_file_sink(expr)
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                self._visit_expr(child)

    def _check_cross_file_sink(self, call: ast.Call) -> None:
        summary = self._summary_for_call(call)
        if summary and (summary.sink_kind_by_param or summary.sink_uses_vararg or summary.sink_uses_kwarg):
            for idx, kind in summary.sink_kind_by_param.items():
                candidate = _argument_for_param(call, summary.params, idx)
                source = self._source_for_expr(candidate) if candidate is not None else _default_source_for_index(summary, idx)
                if not source:
                    continue
                if kind == "sql":
                    self._add("PYXDF001: Cross-file SQL injection", Severity.CRITICAL, call, f"Tainted value from {source} reaches imported SQL wrapper {summary.qualified_name}().", "Use parameterized query APIs and keep SQL sinks behind typed persistence contracts.", summary=summary, source=source)
                elif kind == "shell":
                    self._add("PYXDF002: Cross-file command injection", Severity.CRITICAL, call, f"Tainted value from {source} reaches imported shell wrapper {summary.qualified_name}().", "Use argument lists with shell=False and validate against explicit allow-lists.", summary=summary, source=source)
                elif kind == "html":
                    self._add("PYXDF003: Cross-file template/HTML injection", Severity.HIGH, call, f"Tainted value from {source} reaches imported raw HTML wrapper {summary.qualified_name}().", "Escape untrusted data and avoid helper wrappers around raw template strings.", summary=summary, source=source)
            if summary.sink_uses_vararg:
                for arg in call.args:
                    source = self._source_for_expr(arg)
                    if source:
                        self._add("PYXDF002: Cross-file command injection", Severity.CRITICAL, call, f"Tainted value from {source} reaches imported *args shell wrapper {summary.qualified_name}().", "Use explicit parameters instead of forwarding *args into shell sinks.", summary=summary, source=source)
                        break
            if summary.sink_uses_kwarg:
                for kw in call.keywords:
                    if kw.arg is not None and kw.arg not in {"shell", "timeout"}:
                        source = self._source_for_expr(kw.value)
                        if source:
                            self._add("PYXDF002: Cross-file command injection", Severity.CRITICAL, call, f"Tainted value from {source} reaches imported **kwargs shell wrapper {summary.qualified_name}().", "Use explicit parameters instead of forwarding **kwargs into shell sinks.", summary=summary, source=source)
                            break
            return

        name = self._resolved_name(call.func) or ""
        taint_source = self._source_for_expr(call)
        if not taint_source:
            return
        if is_probable_sql_sink(name):
            query = call.args[0] if call.args else None
            if query is not None and self._source_for_expr(query):
                self._add("PYXDF001: Cross-file SQL injection", Severity.CRITICAL, call, f"Tainted value from {taint_source} reaches SQL execution after a cross-file helper flow.", "Use parameterized queries and avoid forwarding untrusted values through pass-through helpers.")
        elif name in SHELL_SINKS:
            shell_kw = next((kw for kw in call.keywords if kw.arg == "shell"), None)
            shell_true = (isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True) if shell_kw else name == "os.system"
            if shell_true and any(self._source_for_expr(arg) for arg in call.args):
                self._add("PYXDF002: Cross-file command injection", Severity.CRITICAL, call, f"Tainted value from {taint_source} reaches shell execution after a cross-file helper flow.", "Use argument lists with shell=False and avoid forwarding untrusted values through pass-through helpers.")
        elif name in HTML_SINK_NAMES:
            if any(self._source_for_expr(arg) for arg in call.args):
                self._add("PYXDF003: Cross-file template/HTML injection", Severity.HIGH, call, f"Tainted value from {taint_source} reaches raw HTML rendering after a cross-file helper flow.", "Escape untrusted data and avoid forwarding raw HTML through pass-through helpers.")

    def _source_for_expr(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Call):
            name = self._resolved_name(expr.func) or ""
            if name in SANITIZER_CALLS:
                return None
            if name in SOURCE_CALLS:
                return SOURCE_CALLS[name]
            summary = self._summary_for_call(expr)
            if summary:
                if summary.return_source:
                    return f"{summary.qualified_name}()/{summary.return_source}"
                if summary.return_param_index is not None:
                    candidate = _argument_for_param(expr, summary.params, summary.return_param_index)
                    if candidate is not None:
                        return self._source_for_expr(candidate)
                    default_source = _default_source_for_index(summary, summary.return_param_index)
                    if default_source:
                        return f"{summary.qualified_name}()/default:{default_source}"
                if summary.return_vararg:
                    for arg in expr.args:
                        source = self._source_for_expr(arg)
                        if source:
                            return source
                if summary.return_kwarg:
                    for kw in expr.keywords:
                        if kw.arg is not None:
                            source = self._source_for_expr(kw.value)
                            if source:
                                return source
        if isinstance(expr, ast.Attribute):
            return SOURCE_ATTRIBUTES.get(_call_name(expr) or "")
        if isinstance(expr, ast.Subscript):
            return SOURCE_ATTRIBUTES.get(_call_name(expr.value) or "")
        if isinstance(expr, ast.Name):
            return self.tainted.get(expr.id)
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                source = self._source_for_expr(child)
                if source:
                    return source
        return None

    def _summary_for_call(self, call: ast.Call) -> CrossFunctionSummary | None:
        name = self._resolved_name(call.func) or ""
        candidates = [name]
        if name in self.import_map:
            candidates.insert(0, self.import_map[name])
        if "." in name:
            first, rest = name.split(".", 1)
            if first in self.import_map:
                candidates.insert(0, f"{self.import_map[first]}.{rest}")
        for candidate in candidates:
            summary = self.summaries.get(candidate)
            if summary:
                return summary
        return None

    def _constructor_type_for_expr(self, expr: ast.expr) -> str | None:
        if not isinstance(expr, ast.Call):
            return None
        name = self._resolved_name(expr.func) or ""
        if name in self.summaries:
            return None
        # Narrow, deterministic constructor aliasing for imported or local classes.
        # This is not runtime type inference; it only supports simple Name()/Alias() calls.
        raw = _call_name(expr.func) or ""
        if raw[:1].isupper() or name.split(".")[-1:][0][:1].isupper():
            return name
        return None

    def _resolved_name(self, node: ast.AST) -> str | None:
        raw = _call_name(node) or ""
        if not raw:
            return None
        if "." in raw:
            first, rest = raw.split(".", 1)
            if first in self.object_types:
                return f"{self.object_types[first]}.{rest}"
            if first in self.import_map:
                return f"{self.import_map[first]}.{rest}"
        if raw in self.import_map:
            return self.import_map[raw]
        canonical = self.symbols.resolve_name(node).canonical
        return canonical or raw

    def _add(self, category: str, severity: Severity, node: ast.AST, description: str, recommendation: str, *, summary: CrossFunctionSummary | None = None, source: str | None = None) -> None:
        evidence = evidence_for_call(self.symbols, node, reason=category)
        if summary is not None:
            evidence["call_path"] = [self.function.name, summary.qualified_name]
            evidence["taint_path"] = [source or "<unknown-source>", summary.qualified_name]
            evidence["analysis_depth"] = 1
            evidence["unknown_calls"] = 0
        self.issues.append(Issue(
            file=self.payload.relative_path,
            category=category,
            severity=severity,
            detector=PythonCrossFileDataFlowAnalyzer.name,
            description=description,
            recommendation=recommendation,
            location=ast.unparse(node) if hasattr(ast, "unparse") else None,
            line_number=getattr(node, "lineno", None),
            confidence="high" if severity in {Severity.CRITICAL, Severity.HIGH} else "medium",
            evidence=evidence,
        ))


def _build_project_summaries(payloads: list[FilePayload]) -> dict[str, CrossFunctionSummary]:
    summaries: dict[str, CrossFunctionSummary] = {}
    parsed: list[tuple[FilePayload, ast.AST, str, SymbolTable]] = []
    for payload in payloads:
        if payload.path.suffix != ".py":
            continue
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            continue
        parsed.append((payload, tree, _module_name(payload.path, payload.project_root), build_symbol_table(tree)))

    # First pass: direct source/param-return summaries.
    for _payload, tree, module_name, symbols in parsed:
        for qualified, public_alias, fn, params in _iter_exported_functions(tree, module_name):
            return_source, return_param_index, return_vararg, return_kwarg = _summarize_return(fn, params, summaries, symbols)
            vararg = fn.args.vararg.arg if fn.args.vararg else None
            kwarg = fn.args.kwarg.arg if fn.args.kwarg else None
            default_sources_by_index = _default_sources_for_function(fn, params, summaries, symbols)
            summaries[qualified] = CrossFunctionSummary(module_name, public_alias, qualified, params, vararg, kwarg, default_sources_by_index, return_source, return_param_index, return_vararg, return_kwarg, {})
            summaries.setdefault(public_alias, summaries[qualified])

    # Second pass: wrapper sink summaries can use first-pass helper summaries.
    for _payload, tree, module_name, symbols in parsed:
        for qualified, public_alias, fn, params in _iter_exported_functions(tree, module_name):
            previous = summaries.get(qualified)
            vararg = fn.args.vararg.arg if fn.args.vararg else None
            kwarg = fn.args.kwarg.arg if fn.args.kwarg else None
            sink_map, sink_uses_vararg, sink_uses_kwarg = _summarize_sink_wrapper(fn, params, symbols, vararg=vararg, kwarg=kwarg)
            summaries[qualified] = CrossFunctionSummary(module_name, public_alias, qualified, params, vararg, kwarg, previous.default_sources_by_index if previous else {}, previous.return_source if previous else None, previous.return_param_index if previous else None, previous.return_vararg if previous else False, previous.return_kwarg if previous else False, sink_map, sink_uses_vararg, sink_uses_kwarg)
            summaries[public_alias] = summaries[qualified]
    return summaries


def _iter_exported_functions(tree: ast.AST, module_name: str):
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = tuple(arg.arg for arg in node.args.args)
            yield f"{module_name}.{node.name}", node.name, node, params
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    raw = tuple(arg.arg for arg in child.args.args)
                    params = raw[1:] if raw and raw[0] in {"self", "cls"} else raw
                    public = f"{node.name}.{child.name}"
                    yield f"{module_name}.{public}", public, child, params



def _default_source_for_index(summary: CrossFunctionSummary | None, index: int) -> str | None:
    if summary is None:
        return None
    source = summary.default_sources_by_index.get(index)
    return f"default:{source}" if source else None


def _default_sources_for_function(fn: ast.FunctionDef | ast.AsyncFunctionDef, params: tuple[str, ...], summaries: dict[str, CrossFunctionSummary], symbols: SymbolTable) -> dict[int, str]:
    if not fn.args.defaults:
        return {}
    raw_params = tuple(arg.arg for arg in fn.args.args)
    drop_bound_self = bool(raw_params and raw_params[0] in {"self", "cls"} and len(raw_params) == len(params) + 1)
    raw_default_start = len(raw_params) - len(fn.args.defaults)
    out: dict[int, str] = {}
    for raw_idx, default_expr in enumerate(fn.args.defaults, start=raw_default_start):
        if raw_idx < 0 or raw_idx >= len(raw_params):
            continue
        param_index = raw_idx - 1 if drop_bound_self else raw_idx
        if param_index < 0 or param_index >= len(params):
            continue
        source = _expr_source_for_summary(default_expr, params, summaries, symbols)
        if source:
            out[param_index] = source
    return out

def _summarize_return(fn: ast.FunctionDef | ast.AsyncFunctionDef, params: tuple[str, ...], summaries: dict[str, CrossFunctionSummary], symbols: SymbolTable) -> tuple[str | None, int | None, bool, bool]:
    vararg = fn.args.vararg.arg if fn.args.vararg else None
    kwarg = fn.args.kwarg.arg if fn.args.kwarg else None
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and node.value is not None:
            source = _expr_source_for_summary(node.value, params, summaries, symbols, vararg=vararg, kwarg=kwarg)
            if source:
                if source.startswith("param:"):
                    name = source.split(":", 1)[1]
                    if name in params:
                        return None, params.index(name), False, False
                if source == "vararg:*":
                    return None, None, True, False
                if source == "kwarg:**":
                    return None, None, False, True
                return source, None, False, False
    return None, None, False, False


def _summarize_sink_wrapper(fn: ast.FunctionDef | ast.AsyncFunctionDef, params: tuple[str, ...], symbols: SymbolTable, *, vararg: str | None = None, kwarg: str | None = None) -> tuple[dict[int, str], bool, bool]:
    sink_map: dict[int, str] = {}
    sink_uses_vararg = False
    sink_uses_kwarg = False
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = symbols.canonical_call(node) or _call_name(node.func) or ""
        kind: str | None = None
        candidate_exprs: list[ast.expr] = []
        if is_probable_sql_sink(name):
            kind = "sql"
            candidate_exprs = list(node.args[:1]) + [kw.value for kw in node.keywords if kw.arg is None]
        elif name in SHELL_SINKS:
            shell_kw = next((kw for kw in node.keywords if kw.arg == "shell"), None)
            shell_true = (isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True) if shell_kw else name == "os.system"
            if shell_true:
                kind = "shell"
                candidate_exprs = list(node.args) + [kw.value for kw in node.keywords if kw.arg is None]
        elif name in HTML_SINK_NAMES:
            kind = "html"
            candidate_exprs = list(node.args) + [kw.value for kw in node.keywords if kw.arg is None]
        if not kind:
            continue
        for expr in candidate_exprs:
            param = _param_in_expr(expr, params)
            if param is not None:
                sink_map[param] = kind
            if vararg and _contains_name(expr, vararg):
                sink_uses_vararg = True
            if kwarg and _contains_name(expr, kwarg):
                sink_uses_kwarg = True
    return sink_map, sink_uses_vararg, sink_uses_kwarg


def _expr_source_for_summary(expr: ast.expr, params: tuple[str, ...], summaries: dict[str, CrossFunctionSummary], symbols: SymbolTable, *, vararg: str | None = None, kwarg: str | None = None) -> str | None:
    if isinstance(expr, ast.Call):
        name = symbols.canonical_call(expr) or _call_name(expr.func) or ""
        if name in SANITIZER_CALLS:
            return None
        if name in SOURCE_CALLS:
            return SOURCE_CALLS[name]
        summary = summaries.get(name)
        if summary:
            if summary.return_source:
                return f"{summary.qualified_name}()/{summary.return_source}"
            if summary.return_param_index is not None:
                candidate = _argument_for_param(expr, summary.params, summary.return_param_index)
                if candidate is not None:
                    return _expr_source_for_summary(candidate, params, summaries, symbols, vararg=vararg, kwarg=kwarg)
                default_source = _default_source_for_index(summary, summary.return_param_index)
                if default_source:
                    return f"{summary.qualified_name}()/default:{default_source}"
            if summary.return_vararg:
                for arg in expr.args:
                    source = _expr_source_for_summary(arg, params, summaries, symbols, vararg=vararg, kwarg=kwarg)
                    if source:
                        return source
            if summary.return_kwarg:
                for kw in expr.keywords:
                    if kw.arg is not None:
                        source = _expr_source_for_summary(kw.value, params, summaries, symbols, vararg=vararg, kwarg=kwarg)
                        if source:
                            return source
    if isinstance(expr, ast.Attribute):
        direct = SOURCE_ATTRIBUTES.get(symbols.canonical_call(expr) or _call_name(expr) or "")
        if direct:
            return direct
    if isinstance(expr, ast.Subscript):
        direct = SOURCE_ATTRIBUTES.get(symbols.canonical_call(expr.value) or _call_name(expr.value) or "")
        if direct:
            return direct
    if isinstance(expr, ast.Name) and expr.id in params:
        return f"param:{expr.id}"
    if isinstance(expr, ast.Name):
        if vararg and expr.id == vararg:
            return "vararg:*"
        if kwarg and expr.id == kwarg:
            return "kwarg:**"
    for child in ast.iter_child_nodes(expr):
        if isinstance(child, ast.expr):
            source = _expr_source_for_summary(child, params, summaries, symbols, vararg=vararg, kwarg=kwarg)
            if source:
                return source
    return None


def _param_in_expr(expr: ast.expr, params: tuple[str, ...]) -> int | None:
    if isinstance(expr, ast.Call) and (_call_name(expr.func) or "") in SANITIZER_CALLS:
        return None
    if isinstance(expr, ast.Name) and expr.id in params:
        return params.index(expr.id)
    for child in ast.iter_child_nodes(expr):
        if isinstance(child, ast.expr):
            idx = _param_in_expr(child, params)
            if idx is not None:
                return idx
    return None


def _contains_name(expr: ast.AST, name: str) -> bool:
    return any(isinstance(node, ast.Name) and node.id == name for node in ast.walk(expr))


def _build_import_map(tree: ast.AST, current_module: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    package_prefix = current_module.rsplit(".", 1)[0] if "." in current_module else ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                mapping[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module
            if node.level and package_prefix:
                base = f"{package_prefix}.{base}"
            for alias in node.names:
                local = alias.asname or alias.name
                mapping[local] = f"{base}.{alias.name}"
                mapping[f"{local}.{alias.name}"] = f"{base}.{alias.name}"
    return mapping


def _module_name(path: Path, root: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        rel = Path(path.stem)
    parts = [part for part in rel.parts if part != "__init__"]
    return ".".join(parts) if parts else path.stem


def _argument_for_param(call: ast.Call, params: tuple[str, ...], index: int) -> ast.expr | None:
    if index < len(call.args):
        return call.args[index]
    if 0 <= index < len(params):
        param_name = params[index]
        for kw in call.keywords:
            if kw.arg == param_name:
                return kw.value
    return None


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


def _dedupe(issues: list[Issue]) -> list[Issue]:
    seen: set[tuple[str, str, int | None, str | None]] = set()
    out: list[Issue] = []
    for issue in issues:
        key = (issue.file, issue.category, issue.line_number, issue.location)
        if key in seen:
            continue
        seen.add(key)
        out.append(issue)
    return out
