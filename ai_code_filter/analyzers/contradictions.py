from __future__ import annotations

import ast

from .base import Analyzer
from ..models import FilePayload, Issue, Severity


class ContradictionAnalyzer(Analyzer):
    name = "contradictions"

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            return []
        issues: list[Issue] = []
        issues.extend(self._duplicate_functions(payload, tree))
        issues.extend(self._type_contradictions(payload, tree))
        issues.extend(self._docstring_contradictions(payload, tree))
        issues.extend(self._condition_contradictions(payload, tree))
        return issues

    def _duplicate_functions(self, payload: FilePayload, tree: ast.AST) -> list[Issue]:
        # Check duplicates per lexical owner. The original prototype treated every
        # __init__ across different classes as one duplicate, which is a false positive.
        issues: list[Issue] = []

        def check_body(owner: str, body: list[ast.stmt]) -> None:
            seen: dict[str, str] = {}
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    signature = f"{node.name}({', '.join(arg.arg for arg in node.args.args)})"
                    if node.name in seen and seen[node.name] != signature:
                        issues.append(Issue(file=payload.relative_path, category="Duplicate definition contradiction", severity=Severity.CRITICAL, detector=self.name, description=f"Function {owner}.{node.name} is redefined with a different signature.", recommendation="Merge or rename the conflicting functions.", location=ast.unparse(node), line_number=node.lineno))
                    seen.setdefault(node.name, signature)
                if isinstance(node, ast.ClassDef):
                    check_body(node.name, node.body)

        check_body("module", getattr(tree, "body", []))
        return issues

    def _type_contradictions(self, payload: FilePayload, tree: ast.AST) -> list[Issue]:
        annotations: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                annotations[node.target.id] = ast.unparse(node.annotation)
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in annotations and isinstance(node.value, ast.Constant):
                        declared = annotations[target.id].lower().replace(" ", "")
                        value = node.value.value
                        actual = type(value).__name__.lower()
                        if declared in {"int", "float", "str", "bool"} and declared != actual:
                            issues.append(Issue(file=payload.relative_path, category="Type contradiction", severity=Severity.HIGH, detector=self.name, description=f"{target.id} is annotated as {declared} but assigned {actual}.", recommendation="Align the annotation and assigned value.", location=ast.unparse(node), line_number=node.lineno))
        return issues

    def _docstring_contradictions(self, payload: FilePayload, tree: ast.AST) -> list[Issue]:
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                doc = ast.get_docstring(node) or ""
                if "int" in doc.lower() and "return" in doc.lower():
                    has_none = any(isinstance(n, ast.Return) and (n.value is None or isinstance(n.value, ast.Constant) and n.value.value is None) for n in ast.walk(node))
                    if has_none:
                        issues.append(Issue(file=payload.relative_path, category="Docstring contradiction", severity=Severity.MEDIUM, detector=self.name, description="Docstring suggests int return but function can return None.", recommendation="Fix the docstring or return contract.", line_number=node.lineno))
        return issues

    def _condition_contradictions(self, payload: FilePayload, tree: ast.AST) -> list[Issue]:
        issues: list[Issue] = []
        for outer in ast.walk(tree):
            if isinstance(outer, ast.If):
                outer_text = ast.unparse(outer.test)
                for inner in ast.walk(outer):
                    if isinstance(inner, ast.If) and inner is not outer:
                        inner_text = ast.unparse(inner.test)
                        if inner_text in {f"not ({outer_text})", f"not {outer_text}"}:
                            issues.append(Issue(file=payload.relative_path, category="Condition contradiction", severity=Severity.HIGH, detector=self.name, description=f"Contradictory nested conditions: {outer_text} / {inner_text}.", recommendation="Remove unreachable or contradictory branch.", location=ast.unparse(inner), line_number=inner.lineno))
        return issues
