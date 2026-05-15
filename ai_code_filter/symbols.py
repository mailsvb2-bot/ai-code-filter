from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ResolvedSymbol:
    raw: str
    canonical: str
    evidence: tuple[str, ...] = ()


@dataclass
class SymbolTable:
    """Small, deterministic symbol/import resolver used by rules and taint checks.

    It intentionally avoids runtime inference. The contract is narrower and honest:
    normalize import aliases, same-file function aliases, simple assignment aliases,
    and calls through imported modules/classes. Dynamic reflection remains out of scope.
    """

    imports: dict[str, str] = field(default_factory=dict)
    assignments: dict[str, str] = field(default_factory=dict)
    functions: set[str] = field(default_factory=set)
    classes: set[str] = field(default_factory=set)

    @classmethod
    def from_ast(cls, tree: ast.AST | None) -> "SymbolTable":
        table = cls()
        if tree is None:
            return table
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split('.', 1)[0]
                    table.imports[local] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    if alias.name == '*':
                        continue
                    local = alias.asname or alias.name
                    table.imports[local] = f"{node.module}.{alias.name}"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                table.functions.add(node.name)
            elif isinstance(node, ast.ClassDef):
                table.classes.add(node.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                source = table.resolve_name(node.value).canonical
                for target in node.targets:
                    if isinstance(target, ast.Name) and source != target.id:
                        table.assignments[target.id] = source
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute):
                source = table.resolve_name(node.value).canonical
                for target in node.targets:
                    if isinstance(target, ast.Name) and source != target.id:
                        table.assignments[target.id] = source
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                source = table.resolve_call(node.value).canonical
                # Track simple object construction aliases so bound method calls like
                # runner.execute(...) normalize to Runner.execute(...). This is not
                # runtime type inference; it is a narrow same-file constructor alias.
                root = source.split('.', 1)[0] if source else ''
                leaf = source.rsplit('.', 1)[-1] if source else ''
                if source and (root in table.classes or root[:1].isupper() or leaf[:1].isupper()):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and source != target.id:
                            table.assignments[target.id] = source
        return table

    def resolve_name(self, node: ast.AST) -> ResolvedSymbol:
        raw = call_name(node) or ""
        if not raw:
            return ResolvedSymbol(raw="", canonical="")
        root, sep, rest = raw.partition('.')
        evidence: list[str] = []
        mapped = self.imports.get(root) or self.assignments.get(root)
        if mapped:
            evidence.append(f"{root}->{mapped}")
            return ResolvedSymbol(raw=raw, canonical=f"{mapped}.{rest}" if sep else mapped, evidence=tuple(evidence))
        return ResolvedSymbol(raw=raw, canonical=raw)

    def resolve_call(self, call_or_func: ast.AST) -> ResolvedSymbol:
        func = call_or_func.func if isinstance(call_or_func, ast.Call) else call_or_func
        return self.resolve_name(func)

    def canonical_call(self, call_or_func: ast.AST) -> str | None:
        value = self.resolve_call(call_or_func).canonical
        return value or None


def call_name(node: ast.AST) -> str | None:
    """Return dotted AST name for Name/Attribute nodes; None for dynamic expressions."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return call_name(node.func)
    return None


def build_symbol_table(tree: ast.AST | None) -> SymbolTable:
    return SymbolTable.from_ast(tree)


def evidence_for_call(table: SymbolTable, call: ast.Call, *, reason: str) -> dict[str, object]:
    resolved = table.resolve_call(call)
    return {
        "raw_call": resolved.raw,
        "canonical_call": resolved.canonical,
        "alias_evidence": list(resolved.evidence),
        "callsite": ast.unparse(call) if hasattr(ast, "unparse") else None,
        "reason": reason,
    }
