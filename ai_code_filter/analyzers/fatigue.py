from __future__ import annotations

import ast
import re

from .base import Analyzer
from ..models import FilePayload, Issue, Severity


class FatigueAnalyzer(Analyzer):
    name = "fatigue"

    def __init__(self, baseline_comment_ratio: float = 0.1) -> None:
        self.baseline_comment_ratio = baseline_comment_ratio

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.relative_path.startswith("tests/"):
            return []
        index, details = self._compute(payload.content)
        if index <= 0.6:
            return []
        return [Issue(
            file=payload.relative_path,
            category="Fatigue",
            severity=Severity.MEDIUM,
            detector=self.name,
            description=f"Fatigue index {index:.2f}: {', '.join(details)}.",
            recommendation="Add focused documentation, replace TODOs with tracked work, avoid sleep sync, name variables clearly, and use explicit error boundaries.",
        )]

    def _compute(self, code: str) -> tuple[float, list[str]]:
        lines = code.splitlines()
        if not lines:
            return 0.0, []
        comment_density = self.comment_density(code)
        comment_penalty = 0.0 if self.baseline_comment_ratio == 0 else 1.0 - min(1.0, comment_density / self.baseline_comment_ratio)
        todo_score = min(self.todo_count(code) / 10.0, 1.0)
        sleep_score = 1.0 if self.uses_sleep_for_sync(code) else 0.0
        error_absence = self.error_handling_absence(code)
        magic_ratio = self._magic_number_ratio(code)
        short_name_ratio = self._short_name_ratio(code)
        score = (
            comment_penalty * 0.15
            + todo_score * 0.10
            + error_absence * 0.25
            + sleep_score * 0.20
            + magic_ratio * 0.15
            + short_name_ratio * 0.15
        )
        details: list[str] = []
        if comment_penalty > 0.5:
            details.append("low comment density versus project baseline")
        if todo_score > 0:
            details.append("unfinished-work markers")
        if error_absence > 0.7:
            details.append("low explicit error handling around calls")
        if sleep_score:
            details.append("sleep-based synchronization")
        if magic_ratio > 0.1:
            details.append("magic numbers")
        if short_name_ratio > 0.2:
            details.append("short names")
        return min(1.0, max(0.0, score)), details

    @staticmethod
    def comment_density(code: str) -> float:
        lines = code.splitlines()
        return sum(1 for line in lines if line.strip().startswith(("#", "//"))) / len(lines) if lines else 0.0

    @staticmethod
    def todo_count(code: str) -> int:
        return len(re.findall(r"(?:TODO|FIXME|HACK|XXX)\b", code, re.IGNORECASE))

    @staticmethod
    def uses_sleep_for_sync(code: str) -> bool:
        return bool(re.search(r"\b(?:time\.)?sleep\s*\(", code, re.IGNORECASE))

    @staticmethod
    def error_handling_absence(code: str) -> float:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return 0.0
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        tries = [node for node in ast.walk(tree) if isinstance(node, ast.Try)]
        if not calls:
            return 0.0
        return max(0.0, 1.0 - (len(tries) / len(calls)) * 5.0)

    def _magic_number_ratio(self, code: str) -> float:
        lines = code.splitlines()
        if not lines:
            return 0.0
        magic = 0
        allowed = {0, 1, -1, 100, 60, 24, 365}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            values = re.findall(r"\b(-?\d+\.\d+|-?\d+)\b", line)
            if any(float(value) not in allowed for value in values):
                magic += 1
        return magic / len(lines)

    def _short_name_ratio(self, code: str) -> float:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return 0.0
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(node.name)
            elif isinstance(node, ast.Name):
                names.append(node.id)
        return sum(1 for name in names if len(name) <= 2) / len(names) if names else 0.0


def compute_baseline_comment_ratio(payloads: list[FilePayload]) -> float:
    values = [FatigueAnalyzer.comment_density(payload.content) for payload in payloads if payload.content.strip()]
    return sum(values) / len(values) if values else 0.1
