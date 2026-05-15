from __future__ import annotations

import ast

from .base import Analyzer
from ..models import FilePayload, Issue
from ..rules import RuleCatalog, build_default_catalog


class RuleCatalogAnalyzer(Analyzer):
    """Runs deterministic rules from the explicit catalog."""

    name = "rule_catalog"

    def __init__(self, catalog: RuleCatalog | None = None) -> None:
        self.catalog = catalog or build_default_catalog()

    def analyze(self, payload: FilePayload) -> list[Issue]:
        tree: ast.AST | None = None
        if payload.path.suffix == ".py":
            try:
                tree = ast.parse(payload.content)
            except SyntaxError:
                tree = None
        issues: list[Issue] = []
        for rule in self.catalog.for_suffix(payload.path.suffix):
            issues.extend(rule.check(payload, tree))
        return issues
