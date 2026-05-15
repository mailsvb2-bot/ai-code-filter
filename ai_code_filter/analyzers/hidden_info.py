from __future__ import annotations

import ast

from .base import Analyzer
from ..models import FilePayload, Issue, Severity


class HiddenInformationAnalyzer(Analyzer):
    name = "hidden_information"

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            return []
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_") or node.name == "__init__":
                continue
            doc = ast.get_docstring(node) or ""
            has_return_none = any(isinstance(n, ast.Return) and (n.value is None or isinstance(n.value, ast.Constant) and n.value.value is None) for n in ast.walk(node))
            if has_return_none and "none" not in doc.lower():
                issues.append(Issue(file=payload.relative_path, category="Hidden information", severity=Severity.MEDIUM, detector=self.name, description=f"Function {node.name} can return None without documenting it.", recommendation="Document the None case or return a typed result object.", line_number=node.lineno))
            uses_global = any(isinstance(n, ast.Global) for n in ast.walk(node))
            if uses_global and "global" not in doc.lower():
                issues.append(Issue(file=payload.relative_path, category="Hidden information", severity=Severity.HIGH, detector=self.name, description=f"Function {node.name} uses globals without documenting side effects.", recommendation="Remove global mutation or document the side effect contract.", line_number=node.lineno))
            raises = any(isinstance(n, ast.Raise) for n in ast.walk(node))
            if raises and "raise" not in doc.lower() and "raises" not in doc.lower():
                issues.append(Issue(file=payload.relative_path, category="Hidden information", severity=Severity.MEDIUM, detector=self.name, description=f"Function {node.name} raises exceptions without documenting them.", recommendation="Document raised exceptions or use explicit error results.", line_number=node.lineno))
        return issues
