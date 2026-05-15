from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .finding_core import FindingCore
from .models import Issue, Report, Severity


@dataclass(frozen=True)
class MutationCandidate:
    file: str
    line: int
    kind: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "kind": self.kind, "description": self.description}


@dataclass(frozen=True)
class MutationResult:
    candidate: MutationCandidate
    killed: bool
    returncode: int | None
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"candidate": self.candidate.to_dict(), "killed": self.killed, "returncode": self.returncode, "details": self.details}


@dataclass(frozen=True)
class MutationAuditSummary:
    executed: tuple[MutationResult, ...]
    discovered_candidates: int

    def to_dict(self) -> dict[str, Any]:
        killed = sum(1 for item in self.executed if item.killed)
        return {
            "discovered_candidates": self.discovered_candidates,
            "executed": len(self.executed),
            "killed": killed,
            "survived": len(self.executed) - killed,
            "results": [item.to_dict() for item in self.executed],
        }


def audit_mutation_lite(
    project: str | Path,
    *,
    max_mutants: int = 20,
    min_score: float | None = None,
    timeout: int = 1800,
    pytest_args: tuple[str, ...] = (),
    disable_plugin_autoload: bool = True,
) -> tuple[Report, MutationAuditSummary]:
    """Run a conservative mutation-testing smoke gate.

    It executes real pytest against a temporary copy of the project after applying a small set of deterministic mutants.
    Surviving mutants are not a proof of a bug, but they are strong evidence that tests may not verify behavior.
    """
    root = Path(project).resolve()
    report = Report()
    candidates = _discover_candidates(root)
    if not candidates:
        report.add(Issue(
            file=str(root),
            category="MUT001: no mutation candidates discovered",
            severity=Severity.MEDIUM,
            detector="mutation_audit",
            description="No simple return/compare/boolean mutation candidates were found.",
            recommendation="Check whether production files were discovered correctly before claiming mutation coverage.",
            confidence="medium",
            evidence={"project": str(root)},
        ))
        return FindingCore().process(report).report, MutationAuditSummary((), 0)
    executed: list[MutationResult] = []
    for candidate in candidates[: max(0, max_mutants)]:
        result = _execute_mutant(root, candidate, timeout=timeout, pytest_args=pytest_args, disable_plugin_autoload=disable_plugin_autoload)
        executed.append(result)
        if not result.killed:
            severity = Severity.CRITICAL if result.details.get("error") == "timeout" else Severity.HIGH
            report.add(Issue(
                file=candidate.file,
                category="MUT010: mutation survived",
                severity=severity,
                detector="mutation_audit",
                description=f"A {candidate.kind} mutant survived the pytest suite at line {candidate.line}.",
                recommendation="Add behavior tests that would fail when this logic is changed, or mark this candidate as equivalent with a reviewed suppression.",
                line_number=candidate.line,
                confidence="medium",
                evidence={"candidate": candidate.to_dict(), "result": result.to_dict()},
            ))
    if min_score is not None and executed:
        killed = sum(1 for item in executed if item.killed)
        score = (killed / len(executed)) * 100.0
        if score < min_score:
            report.add(Issue(
                file=str(root),
                category="MUT020: mutation score below budget",
                severity=Severity.HIGH,
                detector="mutation_audit",
                description=f"Mutation score is {score:.2f}%, below required {min_score:.2f}%.",
                recommendation="Add tests that kill surviving mutants or reduce the budget with reviewed rationale.",
                confidence="medium",
                evidence={"mutation_score": score, "min_score": min_score, "executed": len(executed), "killed": killed},
            ))
    return FindingCore().process(report).report, MutationAuditSummary(tuple(executed), len(candidates))


def write_mutation_summary(path: str | Path | None, summary: MutationAuditSummary, report: Report) -> None:
    """Write summary JSON when a path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"mutation": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _discover_candidates(root: Path) -> list[MutationCandidate]:
    candidates: list[MutationCandidate] = []
    for path in sorted(root.rglob("*.py")):
        if _is_ignored(path) or _is_test_path(path, root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = _rel(path, root)
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
                candidates.append(MutationCandidate(rel, node.lineno, "return_bool_flip", "Flip boolean return constant"))
            elif isinstance(node, ast.Compare) and node.ops and isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                candidates.append(MutationCandidate(rel, node.lineno, "compare_operator_flip", "Flip the first comparison operator"))
            elif isinstance(node, ast.If) and isinstance(node.test, ast.NameConstant):
                candidates.append(MutationCandidate(rel, node.lineno, "if_constant_flip", "Flip constant if condition"))
    return candidates


def _execute_mutant(root: Path, candidate: MutationCandidate, *, timeout: int, pytest_args: tuple[str, ...], disable_plugin_autoload: bool) -> MutationResult:
    with tempfile.TemporaryDirectory(prefix="aicf_mut_") as tmp:
        work = Path(tmp) / root.name
        shutil.copytree(root, work, ignore=shutil.ignore_patterns(".git", ".venv", "venv", "__pycache__", ".pytest_cache", "*.pyc"))
        target = work / candidate.file
        try:
            _apply_candidate(target, candidate)
        except Exception as exc:
            return MutationResult(candidate, False, None, {"error": f"mutation_apply_failed: {type(exc).__name__}: {exc}"})
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if disable_plugin_autoload:
            env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        env["PYTHONPATH"] = str(work) if not env.get("PYTHONPATH") else f"{work}{os.pathsep}{env['PYTHONPATH']}"
        try:
            proc = subprocess.run([sys.executable, "-m", "pytest", *pytest_args], cwd=str(work), text=True, capture_output=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            return MutationResult(candidate, False, None, {"error": "timeout", "stdout_tail": _tail(_as_text(exc.stdout)), "stderr_tail": _tail(_as_text(exc.stderr))})
        killed = proc.returncode != 0
        return MutationResult(candidate, killed, proc.returncode, {"stdout_tail": _tail(proc.stdout), "stderr_tail": _tail(proc.stderr)})


def _apply_candidate(path: Path, candidate: MutationCandidate) -> None:
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    mutated = _CandidateMutator(candidate).visit(tree)
    ast.fix_missing_locations(mutated)
    path.write_text(ast.unparse(mutated) + "\n", encoding="utf-8")


class _CandidateMutator(ast.NodeTransformer):
    def __init__(self, candidate: MutationCandidate) -> None:
        self.candidate = candidate
        self.done = False

    def visit_Return(self, node: ast.Return) -> ast.AST:
        if not self.done and self.candidate.kind == "return_bool_flip" and node.lineno == self.candidate.line and isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
            self.done = True
            return ast.copy_location(ast.Return(value=ast.Constant(value=not node.value.value)), node)
        return self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        if not self.done and self.candidate.kind == "compare_operator_flip" and node.lineno == self.candidate.line and node.ops:
            self.done = True
            first = node.ops[0]
            replacement: ast.cmpop
            if isinstance(first, ast.Eq):
                replacement = ast.NotEq()
            elif isinstance(first, ast.NotEq):
                replacement = ast.Eq()
            elif isinstance(first, ast.Lt):
                replacement = ast.GtE()
            elif isinstance(first, ast.LtE):
                replacement = ast.Gt()
            elif isinstance(first, ast.Gt):
                replacement = ast.LtE()
            else:
                replacement = ast.Lt()
            node.ops[0] = replacement
            return node
        return self.generic_visit(node)

    def visit_If(self, node: ast.If) -> ast.AST:
        if not self.done and self.candidate.kind == "if_constant_flip" and node.lineno == self.candidate.line and isinstance(node.test, ast.NameConstant):
            self.done = True
            node.test = ast.Constant(value=not bool(node.test.value))
            return node
        return self.generic_visit(node)


def _is_test_path(path: Path, root: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        parts = path.parts
    return "tests" in parts or path.name.startswith("test_") or path.name.endswith("_test.py")


def _is_ignored(path: Path) -> bool:
    ignored = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}
    return any(part in ignored for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _tail(text: str, max_chars: int = 5000) -> str:
    return text[-max_chars:] if len(text) > max_chars else text
