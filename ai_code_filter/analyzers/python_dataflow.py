from __future__ import annotations

import ast
from dataclasses import dataclass

from .base import Analyzer
from ..models import FilePayload, Issue, Severity
from ..symbols import SymbolTable, build_symbol_table, call_name as _symbol_call_name, evidence_for_call


@dataclass(frozen=True)
class _Taint:
    name: str
    source: str
    line_number: int | None = None


@dataclass(frozen=True)
class _WrapperSink:
    sink_name: str
    arg_index: int | None = None
    keyword: str | None = None
    forwarded_vararg: bool = False
    forwarded_kwarg: bool = False
    shell_true: bool = False


@dataclass(frozen=True)
class _FunctionSummary:
    name: str
    params: tuple[str, ...]
    vararg: str | None = None
    kwarg: str | None = None
    default_sources_by_index: dict[int, str] | None = None
    return_source: str | None = None
    return_param_index: int | None = None
    return_vararg: bool = False
    return_kwarg: bool = False
    wrapper_sink: _WrapperSink | None = None


SOURCE_CALLS = {
    "input": "stdin/input",
    "request.args.get": "flask-request-args",
    "request.form.get": "flask-request-form",
    "request.values.get": "flask-request-values",
    "request.cookies.get": "flask-cookie",
    "request.headers.get": "http-header",
    "request.get_json": "flask-json-body",
    "flask.request.args.get": "flask-request-args",
    "flask.request.form.get": "flask-request-form",
    "flask.request.values.get": "flask-request-values",
    "flask.request.cookies.get": "flask-cookie",
    "flask.request.headers.get": "http-header",
    "flask.request.get_json": "flask-json-body",
    "os.getenv": "environment-variable",
    "os.environ.get": "environment-variable",
}
SOURCE_ATTRIBUTES = {
    "request.args": "flask-request-args",
    "request.form": "flask-request-form",
    "request.values": "flask-request-values",
    "request.cookies": "flask-cookie",
    "request.headers": "http-header",
    "request.json": "flask-json-body",
    "sys.argv": "process-argv",
}
SANITIZER_CALLS = {
    "html.escape",
    "markupsafe.escape",
    "escape",
    "shlex.quote",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
}
SQL_SINK_SUFFIXES = ("execute", "executemany")


def is_probable_sql_sink(name: str) -> bool:
    """Conservative SQL sink heuristic.

    Avoid treating arbitrary OO methods such as Runner.execute() as database sinks.
    This intentionally keeps precision higher: direct cursor/connection-style execute calls
    and module-level execute helpers are covered; capitalized class methods are not treated
    as SQL unless wrapped by an explicit summary.
    """
    if not name.endswith(SQL_SINK_SUFFIXES):
        return False
    parts = name.split(".")
    root = parts[0]
    owner = parts[-2] if len(parts) >= 2 else ""
    if root[:1].isupper() or owner[:1].isupper():
        return False
    return True
SHELL_SINKS = {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"}
HTML_SINK_NAMES = {"render_template_string", "flask.render_template_string", "markupsafe.Markup", "Markup"}


class PythonDataFlowAnalyzer(Analyzer):
    """Conservative Python taint checks with local and small inter-function summaries.

    This is still not a full static-analysis engine. It deliberately reports only direct,
    explainable source→sink paths: assignments, derived expressions, helper function returns,
    and helper wrappers that pass tainted arguments to risky sinks. Import aliases are
    normalized so ``from subprocess import run`` is treated like ``subprocess.run``.
    """

    name = "python_dataflow"

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            return []
        symbols = build_symbol_table(tree)
        summaries = _build_function_summaries(tree, symbols)
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                issues.extend(_FunctionTaintPass(payload, node, summaries, symbols).run())
        return _dedupe(issues)


class _FunctionTaintPass:
    def __init__(self, payload: FilePayload, function: ast.FunctionDef | ast.AsyncFunctionDef, summaries: dict[str, _FunctionSummary], symbols: SymbolTable) -> None:
        self.payload = payload
        self.function = function
        self.summaries = summaries
        self.symbols = symbols
        self.tainted: dict[str, _Taint] = {}
        self.issues: list[Issue] = []

    def run(self) -> list[Issue]:
        for stmt in self.function.body:
            self._visit_stmt(stmt)
        return self.issues

    def _visit_stmt(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            self._handle_assignment(stmt)
        elif isinstance(stmt, ast.AugAssign):
            self._handle_aug_assignment(stmt)
        elif isinstance(stmt, ast.For):
            self._visit_expr(stmt.iter)
            if isinstance(stmt.target, ast.Name) and self._expr_contains_tainted(stmt.iter):
                self.tainted[stmt.target.id] = _Taint(stmt.target.id, self._taint_source_in_expr(stmt.iter) or "derived-taint", getattr(stmt, "lineno", None))
            for child in stmt.body + stmt.orelse:
                self._visit_stmt(child)
        elif isinstance(stmt, ast.While):
            self._visit_expr(stmt.test)
            for child in stmt.body + stmt.orelse:
                self._visit_stmt(child)
        elif isinstance(stmt, ast.If):
            self._visit_expr(stmt.test)
            # Conservative branch merge: we keep taint from either branch, and remove taint only
            # when both branches overwrite a variable with clean values. This avoids unsafe false negatives.
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
        elif isinstance(stmt, ast.Try):
            for child in stmt.body + stmt.orelse + stmt.finalbody:
                self._visit_stmt(child)
            for handler in stmt.handlers:
                for child in handler.body:
                    self._visit_stmt(child)
        elif isinstance(stmt, ast.With):
            for item in stmt.items:
                self._visit_expr(item.context_expr)
            for child in stmt.body:
                self._visit_stmt(child)
        elif isinstance(stmt, ast.Return):
            if stmt.value:
                self._visit_expr(stmt.value)
        elif isinstance(stmt, ast.Expr):
            self._visit_expr(stmt.value)
        else:
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self._visit_expr(child)

    def _handle_assignment(self, stmt: ast.Assign | ast.AnnAssign) -> None:
        value = stmt.value
        if value is None:
            return
        self._visit_expr(value)
        source = self._source_for_expr(value) or self._taint_source_in_expr(value)
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        for target in targets:
            for target_name in _target_names(target):
                if source:
                    self.tainted[target_name] = _Taint(target_name, source, getattr(stmt, "lineno", None))
                elif target_name in self.tainted and not self._expr_contains_tainted(value):
                    self.tainted.pop(target_name, None)

    def _handle_aug_assignment(self, stmt: ast.AugAssign) -> None:
        self._visit_expr(stmt.value)
        if isinstance(stmt.target, ast.Name) and self._expr_contains_tainted(stmt.value):
            self.tainted[stmt.target.id] = _Taint(stmt.target.id, self._taint_source_in_expr(stmt.value) or "derived-taint", getattr(stmt, "lineno", None))

    def _visit_expr(self, expr: ast.expr) -> None:
        if isinstance(expr, ast.Call):
            self._check_sink(expr)
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                self._visit_expr(child)

    def _check_sink(self, call: ast.Call) -> None:
        name = _resolved_call_name(call.func, self.symbols) or ""
        summary = self.summaries.get(name)
        taint_source = self._taint_source_in_call_args(call) or _default_taint_for_call(call, summary)
        if not taint_source:
            return
        if summary and summary.wrapper_sink:
            sink = summary.wrapper_sink
            tainted_arg = False
            if sink.arg_index is not None:
                candidate = _argument_for_param(call, summary.params, sink.arg_index)
                tainted_arg = bool(candidate is not None and self._expr_contains_tainted(candidate))
                if not tainted_arg and candidate is None:
                    tainted_arg = bool(_default_source_for_index(summary, sink.arg_index))
            if sink.keyword is not None:
                for kw in call.keywords:
                    if kw.arg == sink.keyword and self._expr_contains_tainted(kw.value):
                        tainted_arg = True
            if sink.forwarded_vararg and any(self._expr_contains_tainted(arg) for arg in call.args):
                tainted_arg = True
            if sink.forwarded_kwarg:
                for kw in call.keywords:
                    if kw.arg is not None and kw.arg not in {"shell", "timeout"} and self._expr_contains_tainted(kw.value):
                        tainted_arg = True
            if tainted_arg and sink.sink_name in SHELL_SINKS and sink.shell_true:
                self._add("PYDF002: Data-flow command injection", Severity.CRITICAL, call, f"Tainted value from {taint_source} reaches shell wrapper {summary.name}().", "Inline or harden the wrapper: shell=False, argument lists, timeout, and allow-list validation.")
                return
            if tainted_arg and is_probable_sql_sink(sink.sink_name):
                self._add("PYDF001: Data-flow SQL injection", Severity.CRITICAL, call, f"Tainted value from {taint_source} reaches SQL wrapper {summary.name}().", "Use parameterized queries inside wrappers and make wrapper contracts explicit.")
                return
        if is_probable_sql_sink(name):
            query = call.args[0] if call.args else None
            if query is not None and self._expr_contains_tainted(query):
                self._add("PYDF001: Data-flow SQL injection", Severity.CRITICAL, call, f"Tainted value from {taint_source} reaches SQL execution.", "Use parameterized queries and validate/normalize input before persistence boundaries.")
        elif name in SHELL_SINKS:
            shell_kw = next((kw for kw in call.keywords if kw.arg == "shell"), None)
            shell_true = (isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True) if shell_kw else name == "os.system"
            if shell_true and any(self._expr_contains_tainted(arg) for arg in call.args):
                self._add("PYDF002: Data-flow command injection", Severity.CRITICAL, call, f"Tainted value from {taint_source} reaches shell execution.", "Use argument lists with shell=False and strict allow-list validation.")
        elif name in HTML_SINK_NAMES:
            if any(self._expr_contains_tainted(arg) for arg in call.args):
                self._add("PYDF003: Data-flow template injection", Severity.HIGH, call, f"Tainted value from {taint_source} reaches raw template/HTML sink.", "Use escaped templates and avoid rendering user-controlled template strings.")
    def _source_for_expr(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Call):
            call_name = _resolved_call_name(expr.func, self.symbols) or ""
            if call_name in SANITIZER_CALLS:
                return None
            direct = SOURCE_CALLS.get(call_name)
            if direct:
                return direct
            summary = self.summaries.get(call_name)
            if summary:
                if summary.return_source:
                    return f"{summary.name}()/{summary.return_source}"
                if summary.return_param_index is not None:
                    candidate = _argument_for_param(expr, summary.params, summary.return_param_index)
                    if candidate is not None:
                        return self._taint_source_in_expr(candidate)
                    default_source = _default_source_for_index(summary, summary.return_param_index)
                    if default_source:
                        return f"{summary.name}()/default:{default_source}"
                if summary.return_vararg:
                    for arg in expr.args:
                        source = self._taint_source_in_expr(arg)
                        if source:
                            return source
                if summary.return_kwarg:
                    for kw in expr.keywords:
                        if kw.arg is not None:
                            source = self._taint_source_in_expr(kw.value)
                            if source:
                                return source
        if isinstance(expr, ast.Attribute):
            return SOURCE_ATTRIBUTES.get(_resolved_call_name(expr, self.symbols) or "")
        if isinstance(expr, ast.Subscript):
            return SOURCE_ATTRIBUTES.get(_resolved_call_name(expr.value, self.symbols) or "")
        return None

    def _taint_source_in_expr(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Call) and (_resolved_call_name(expr.func, self.symbols) or "") in SANITIZER_CALLS:
            return None
        direct = self._source_for_expr(expr)
        if direct:
            return direct
        if isinstance(expr, ast.Name) and expr.id in self.tainted:
            return self.tainted[expr.id].source
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                child_source = self._taint_source_in_expr(child)
                if child_source:
                    return child_source
        return None

    def _taint_source_in_call_args(self, call: ast.Call) -> str | None:
        for arg in call.args:
            source = self._taint_source_in_expr(arg)
            if source:
                return source
        for kw in call.keywords:
            source = self._taint_source_in_expr(kw.value)
            if source:
                return source
        return None

    def _expr_contains_tainted(self, expr: ast.expr) -> bool:
        return self._taint_source_in_expr(expr) is not None

    def _add(self, category: str, severity: Severity, node: ast.AST, description: str, recommendation: str) -> None:
        self.issues.append(Issue(
            file=self.payload.relative_path,
            category=category,
            severity=severity,
            detector="python_dataflow",
            description=description,
            recommendation=recommendation,
            location=ast.unparse(node) if hasattr(ast, "unparse") else None,
            line_number=getattr(node, "lineno", None),
            confidence="high" if severity in {Severity.CRITICAL, Severity.HIGH} else "medium",
            evidence=evidence_for_call(self.symbols, node, reason=category),
        ))


def _build_function_summaries(tree: ast.AST, symbols: SymbolTable) -> dict[str, _FunctionSummary]:
    summaries: dict[str, _FunctionSummary] = {}

    def summarize(fn: ast.FunctionDef | ast.AsyncFunctionDef, *, public_name: str, drop_bound_self: bool = False) -> None:
        raw_params = tuple(arg.arg for arg in fn.args.args)
        params = raw_params[1:] if drop_bound_self and raw_params and raw_params[0] in {"self", "cls"} else raw_params
        vararg = fn.args.vararg.arg if fn.args.vararg else None
        kwarg = fn.args.kwarg.arg if fn.args.kwarg else None
        resolver = _SummaryExprResolver(params, summaries, symbols, vararg=vararg, kwarg=kwarg)
        default_sources_by_index = _default_sources_for_function(fn, raw_params, params, resolver, drop_bound_self=drop_bound_self)
        return_source: str | None = None
        return_param_index: int | None = None
        return_vararg = False
        return_kwarg = False
        wrapper_sink: _WrapperSink | None = None
        for stmt in fn.body:
            resolver.visit_statement(stmt)
        for node in ast.walk(fn):
            if isinstance(node, ast.Return) and node.value is not None:
                local = resolver.source_for_expr(node.value)
                if local:
                    if local.startswith("param:"):
                        pname = local.split(":", 1)[1]
                        if pname in params:
                            return_param_index = params.index(pname)
                    elif local == "vararg:*":
                        return_vararg = True
                    elif local == "kwarg:**":
                        return_kwarg = True
                    else:
                        return_source = local
            if isinstance(node, ast.Call):
                name = symbols.canonical_call(node) or ""
                sink = _wrapper_sink_for_call(name, node, params, vararg, kwarg)
                if sink is not None:
                    wrapper_sink = sink
        summaries[public_name] = _FunctionSummary(public_name, params, vararg, kwarg, default_sources_by_index, return_source, return_param_index, return_vararg, return_kwarg, wrapper_sink)

    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            summarize(node, public_name=node.name)
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    summarize(child, public_name=f"{node.name}.{child.name}", drop_bound_self=True)
    return summaries



def _default_source_for_index(summary: _FunctionSummary | None, index: int) -> str | None:
    if summary is None or summary.default_sources_by_index is None:
        return None
    return summary.default_sources_by_index.get(index)


def _default_taint_for_call(call: ast.Call, summary: _FunctionSummary | None) -> str | None:
    if summary is None or not summary.default_sources_by_index:
        return None
    for idx, source in summary.default_sources_by_index.items():
        if _argument_for_param(call, summary.params, idx) is None:
            return f"{summary.name}()/default:{source}"
    return None


def _default_sources_for_function(fn: ast.FunctionDef | ast.AsyncFunctionDef, raw_params: tuple[str, ...], params: tuple[str, ...], resolver: _SummaryExprResolver, *, drop_bound_self: bool = False) -> dict[int, str]:
    if not fn.args.defaults:
        return {}
    raw_default_start = len(raw_params) - len(fn.args.defaults)
    out: dict[int, str] = {}
    for raw_idx, default_expr in enumerate(fn.args.defaults, start=raw_default_start):
        if raw_idx < 0 or raw_idx >= len(raw_params):
            continue
        param_name = raw_params[raw_idx]
        if drop_bound_self and raw_params and raw_params[0] in {"self", "cls"}:
            if raw_idx == 0:
                continue
            param_index = raw_idx - 1
        else:
            param_index = raw_idx
        if param_index < 0 or param_index >= len(params):
            continue
        source = resolver.source_for_expr(default_expr)
        if source:
            out[param_index] = source
    return out

def _wrapper_sink_for_call(name: str, call: ast.Call, params: tuple[str, ...], vararg: str | None = None, kwarg: str | None = None) -> _WrapperSink | None:
    if name not in SHELL_SINKS and not is_probable_sql_sink(name):
        return None
    shell_true = name == "os.system"
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            shell_true = True
    for idx, arg in enumerate(call.args):
        if isinstance(arg, ast.Name) and arg.id in params:
            return _WrapperSink(name, arg_index=params.index(arg.id), shell_true=shell_true)
        if isinstance(arg, ast.Starred) and isinstance(arg.value, ast.Name) and vararg and arg.value.id == vararg:
            return _WrapperSink(name, forwarded_vararg=True, shell_true=shell_true)
    for kw in call.keywords:
        if kw.arg is None and isinstance(kw.value, ast.Name) and kwarg and kw.value.id == kwarg:
            return _WrapperSink(name, forwarded_kwarg=True, shell_true=shell_true)
        if isinstance(kw.value, ast.Name) and kw.value.id in params:
            return _WrapperSink(name, keyword=kw.arg, shell_true=shell_true)
    return None


class _SummaryExprResolver:
    def __init__(self, params: tuple[str, ...], summaries: dict[str, _FunctionSummary], symbols: SymbolTable, *, vararg: str | None = None, kwarg: str | None = None) -> None:
        self.params = params
        self.vararg = vararg
        self.kwarg = kwarg
        self.summaries = summaries
        self.symbols = symbols
        self.locals: dict[str, str] = {}

    def visit_statement(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
            source = self.source_for_expr(stmt.value)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                for target_name in _target_names(target):
                    if source:
                        self.locals[target_name] = source
                    else:
                        self.locals.pop(target_name, None)
        elif isinstance(stmt, ast.If):
            for child in stmt.body + stmt.orelse:
                self.visit_statement(child)
        elif isinstance(stmt, ast.Try):
            for child in stmt.body + stmt.orelse + stmt.finalbody:
                self.visit_statement(child)
            for handler in stmt.handlers:
                for child in handler.body:
                    self.visit_statement(child)

    def source_for_expr(self, expr: ast.expr) -> str | None:
        """Provides source text; None means clean or unknown."""
        if isinstance(expr, ast.Call):
            name = self.symbols.canonical_call(expr) or ""
            if name in SANITIZER_CALLS:
                return None
            if name in SOURCE_CALLS:
                return SOURCE_CALLS[name]
            summary = self.summaries.get(name)
            if summary:
                if summary.return_source:
                    return f"{summary.name}()/{summary.return_source}"
                if summary.return_param_index is not None:
                    candidate = _argument_for_param(expr, summary.params, summary.return_param_index)
                    if candidate is not None:
                        return self.source_for_expr(candidate)
                    default_source = _default_source_for_index(summary, summary.return_param_index)
                    if default_source:
                        return f"{summary.name}()/default:{default_source}"
                if summary.return_vararg:
                    for arg in expr.args:
                        source = self.source_for_expr(arg)
                        if source:
                            return source
                if summary.return_kwarg:
                    for kw in expr.keywords:
                        if kw.arg is not None:
                            source = self.source_for_expr(kw.value)
                            if source:
                                return source
        if isinstance(expr, ast.Attribute):
            direct = SOURCE_ATTRIBUTES.get(self.symbols.canonical_call(expr) or "")
            if direct:
                return direct
        if isinstance(expr, ast.Subscript):
            direct = SOURCE_ATTRIBUTES.get(self.symbols.canonical_call(expr.value) or "")
            if direct:
                return direct
        if isinstance(expr, ast.Name):
            if expr.id in self.params:
                return f"param:{expr.id}"
            if self.vararg and expr.id == self.vararg:
                return "vararg:*"
            if self.kwarg and expr.id == self.kwarg:
                return "kwarg:**"
            return self.locals.get(expr.id)
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                source = self.source_for_expr(child)
                if source:
                    return source
        return None

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


def _call_name(node: ast.AST) -> str | None:
    return _symbol_call_name(node)


def _resolved_call_name(node: ast.AST, symbols: SymbolTable) -> str | None:
    return symbols.canonical_call(node)


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
