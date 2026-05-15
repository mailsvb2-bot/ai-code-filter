from __future__ import annotations

import ast
import math
import re
from collections import Counter

from .base import Analyzer
from ..models import FilePayload, Issue, Severity


class PoliteAnnoyanceAnalyzer(Analyzer):
    name = "polite_annoyance"

    def __init__(self, baseline_entropy: float = 1.5) -> None:
        self.baseline_entropy = baseline_entropy

    def analyze(self, payload: FilePayload) -> list[Issue]:
        score, details = self._score(payload.content)
        if score <= 0.6:
            return []
        return [Issue(
            file=payload.relative_path,
            category="Silent suppression / overdefensive code",
            severity=Severity.HIGH,
            detector=self.name,
            description=f"Annoyance index {score:.2f}: {', '.join(details)}.",
            recommendation="Replace silent suppression with explicit errors, remove apologetic comments, and convert defensive overchecks into typed contracts.",
        )]

    def _score(self, code: str) -> tuple[float, list[str]]:
        esi = self.error_suppression_index(code)
        dor = self.defensive_overcheck_ratio(code)
        acr = self.apologetic_comment_ratio(code)
        entropy_anomaly = self.branching_entropy_anomaly(code)
        score = min(1.0, esi * 0.40 + dor * 0.25 + acr * 0.15 + entropy_anomaly * 0.20)
        details: list[str] = []
        if esi > 0.3:
            details.append("error suppression")
        if dor > 0.5:
            details.append("defensive overchecks")
        if acr > 0:
            details.append("apologetic comments")
        if entropy_anomaly > 0.5:
            details.append("branching entropy anomaly")
        return score, details

    @staticmethod
    def error_suppression_index(code: str) -> float:
        raises = len(re.findall(r"\braise\s+\w+", code))
        silent = len(re.findall(r"except\s*(?:Exception)?\s*:\s*pass|except\s*(?:Exception)?\s*:\s*return\s+(?:None|False|\[\]|\{\})", code, re.DOTALL))
        total = raises + silent
        return silent / total if total else 0.0

    @staticmethod
    def defensive_overcheck_ratio(code: str) -> float:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return 0.0
        ifs = [node for node in ast.walk(tree) if isinstance(node, ast.If)]
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        expected_guards = sum(len(fn.args.args) + len(fn.args.kwonlyargs) for fn in functions)
        return max(0.0, (len(ifs) - expected_guards) / len(ifs)) if ifs else 0.0

    @staticmethod
    def apologetic_comment_ratio(code: str) -> float:
        count = len(re.findall(r"пока\s+так|временно|костыль|чтобы\s+не\s+сломать|на\s+всякий\s+случай", code, re.IGNORECASE))
        return count / max(1, len(code.splitlines()))

    def branching_entropy_anomaly(self, code: str) -> float:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return 0.0
        branch_counts: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                branch_counts.append(sum(1 for n in ast.walk(node) if isinstance(n, ast.If)))
        if not branch_counts:
            return 0.0
        histogram = Counter(branch_counts)
        total = len(branch_counts)
        entropy = -sum((count / total) * math.log2(count / total) for count in histogram.values())
        return min(1.0, abs(entropy - self.baseline_entropy))


def compute_baseline_branch_entropy(payloads: list[FilePayload]) -> float:
    entropies: list[float] = []
    detector = PoliteAnnoyanceAnalyzer(0.0)
    for payload in payloads:
        if payload.path.suffix == ".py":
            try:
                tree = ast.parse(payload.content)
            except SyntaxError:
                continue
            counts = [sum(1 for n in ast.walk(node) if isinstance(n, ast.If)) for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if counts:
                histogram = Counter(counts)
                total = len(counts)
                entropies.append(-sum((count / total) * math.log2(count / total) for count in histogram.values()))
    return sum(entropies) / len(entropies) if entropies else detector.baseline_entropy
