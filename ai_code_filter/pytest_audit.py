from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .finding_core import FindingCore
from .models import Issue, Report, Severity


SUMMARY_RE = re.compile(r"(?P<count>\d+)\s+(?P<kind>passed|failed|skipped|xfailed|xpassed|errors?|warnings?)")
TEST_FILE_PATTERNS = ("test_*.py", "*_test.py")


@dataclass(frozen=True)
class ProductionSymbol:
    file: str
    module: str
    name: str
    kind: str
    line_number: int
    branch_count: int = 0
    raises_count: int = 0

    @property
    def qualified_name(self) -> str:
        return f"{self.module}.{self.name}" if self.module else self.name


@dataclass(frozen=True)
class TestSemanticSignals:
    test_files: tuple[str, ...] = ()
    imported_modules: frozenset[str] = field(default_factory=frozenset)
    referenced_names: frozenset[str] = field(default_factory=frozenset)
    assert_count: int = 0
    weak_assert_count: int = 0
    exception_assert_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_files": list(self.test_files),
            "imported_modules": sorted(self.imported_modules),
            "referenced_names": sorted(self.referenced_names),
            "assert_count": self.assert_count,
            "weak_assert_count": self.weak_assert_count,
            "exception_assert_count": self.exception_assert_count,
        }


@dataclass(frozen=True)
class PytestRunSummary:
    returncode: int
    timed_out: bool
    duration_seconds: float | None
    counts: dict[str, int]
    command: tuple[str, ...]
    stdout_tail: str
    stderr_tail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "duration_seconds": self.duration_seconds,
            "counts": dict(self.counts),
            "command": list(self.command),
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
        }


def audit_pytest(
    project: str | Path,
    *,
    timeout: int = 1800,
    run: bool = True,
    extra_args: Iterable[str] = (),
    disable_plugin_autoload: bool = True,
    semantic_completeness: bool = False,
    min_public_coverage: float = 0.35,
) -> tuple[Report, PytestRunSummary | None]:
    """Run pytest and audit common test-suite truthfulness hazards.

    This is intentionally not a full test-quality theorem prover. It provides a
    deterministic CI helper for the risks this project cares about: failed test
    runs, masking via skip/xfail, decorative/import-only tests, broad
    exception swallowing in tests, and optional semantic completeness signals.

    Semantic completeness is heuristic. It does not prove behavioral coverage; it
    checks whether tests reference production symbols/modules, whether public API
    coverage is suspiciously low, whether obvious error paths have exception
    assertions, and whether assertions are purely decorative.
    """
    root = Path(project)
    report = Report()
    report.extend(_static_test_audit(root))
    if semantic_completeness:
        report.extend(_semantic_completeness_audit(root, min_public_coverage=min_public_coverage))
    summary: PytestRunSummary | None = None
    if run:
        summary = _run_pytest(root, timeout=timeout, extra_args=tuple(extra_args), disable_plugin_autoload=disable_plugin_autoload)
        report.extend(_issues_from_run(root, summary))
    core_result = FindingCore().process(report)
    return core_result.report, summary


def write_pytest_summary(path: str | Path | None, summary: PytestRunSummary | None, report: Report) -> None:
    """Write optional pytest summary JSON; returns None when no output path is provided."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "pytest": summary.to_dict() if summary else None,
        "audit_summary": report.summary(),
        "issues": [issue.to_dict() for issue in report.issues],
    }
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")



def _semantic_completeness_audit(root: Path, *, min_public_coverage: float) -> list[Issue]:
    """Heuristic semantic completeness audit for pytest suites.

    This deliberately avoids claiming proof of completeness. It compares public
    production symbols with the semantic signals visible in tests: imports,
    references, assertion quality, and exception-path assertions.
    """
    production_symbols = _collect_production_symbols(root)
    tests = _discover_test_files(root)
    signals = _collect_test_semantic_signals(root, tests)
    issues: list[Issue] = []
    if not production_symbols:
        return issues
    public_symbols = [s for s in production_symbols if not _is_private_symbol(s.name)]
    covered = [s for s in public_symbols if _symbol_is_referenced(s, signals)]
    coverage_ratio = (len(covered) / len(public_symbols)) if public_symbols else 1.0
    evidence = {
        "public_symbols": len(public_symbols),
        "covered_public_symbols": len(covered),
        "coverage_ratio": round(coverage_ratio, 3),
        "semantic_signals": signals.to_dict(),
        "uncovered_sample": [s.qualified_name for s in public_symbols if not _symbol_is_referenced(s, signals)][:20],
    }
    if signals.test_files and not signals.imported_modules and not any(_symbol_is_referenced(s, signals) for s in public_symbols):
        issues.append(Issue(
            file=str(root),
            category="PYTEST030: no semantic production references",
            severity=Severity.HIGH,
            detector="pytest_semantic_completeness",
            description="Tests were found, but they do not appear to import or reference production modules/symbols.",
            recommendation="Add behavioral tests that import production code and assert externally visible behavior.",
            confidence="medium",
            evidence=evidence,
        ))
    elif coverage_ratio < min_public_coverage and len(public_symbols) >= 3:
        issues.append(Issue(
            file=str(root),
            category="PYTEST031: low public API semantic coverage",
            severity=Severity.MEDIUM,
            detector="pytest_semantic_completeness",
            description=(
                f"Only {len(covered)}/{len(public_symbols)} public production symbols appear to be referenced by tests "
                f"({coverage_ratio:.0%})."
            ),
            recommendation="Add tests that exercise uncovered public functions/classes or lower the explicit threshold with justification.",
            confidence="medium",
            evidence=evidence,
        ))
    for symbol in public_symbols:
        if _symbol_is_referenced(symbol, signals):
            continue
        if symbol.branch_count >= 2 or symbol.raises_count:
            issues.append(Issue(
                file=symbol.file,
                category="PYTEST032: complex production symbol lacks direct test reference",
                severity=Severity.MEDIUM,
                detector="pytest_semantic_completeness",
                description=f"{symbol.qualified_name} has branch/error-path signals but no direct test reference was found.",
                recommendation="Add tests that cover nominal, edge, and error behavior for this symbol.",
                location=f"{symbol.name}:{symbol.line_number}",
                line_number=symbol.line_number,
                confidence="medium",
                evidence={
                    "symbol": symbol.qualified_name,
                    "branch_count": symbol.branch_count,
                    "raises_count": symbol.raises_count,
                    "semantic_signals": signals.to_dict(),
                },
            ))
    raise_symbols = [s for s in public_symbols if s.raises_count and _symbol_is_referenced(s, signals)]
    if raise_symbols and signals.exception_assert_count == 0:
        issues.append(Issue(
            file=str(root),
            category="PYTEST033: error paths lack exception assertions",
            severity=Severity.MEDIUM,
            detector="pytest_semantic_completeness",
            description="Production code contains explicit raise paths, but tests show no pytest.raises/unittest exception assertion signal.",
            recommendation="Add negative-path tests that assert the expected exception type and message/contract.",
            confidence="medium",
            evidence={"raise_symbols": [s.qualified_name for s in raise_symbols[:20]], "semantic_signals": signals.to_dict()},
        ))
    if signals.assert_count and signals.weak_assert_count == signals.assert_count:
        issues.append(Issue(
            file=str(root),
            category="PYTEST034: only weak/decorative assertions detected",
            severity=Severity.MEDIUM,
            detector="pytest_semantic_completeness",
            description="All detected assertions look tautological or weak, such as assert True / assert 1 == 1.",
            recommendation="Assert concrete outputs, state transitions, side effects, or exception contracts from production behavior.",
            confidence="medium",
            evidence=signals.to_dict(),
        ))
    return issues


def _collect_production_symbols(root: Path) -> list[ProductionSymbol]:
    symbols: list[ProductionSymbol] = []
    for path in _discover_python_files(root):
        if _is_test_path(path, root):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.append(_symbol_from_node(path, root, module, node, node.name, "function"))
            elif isinstance(node, ast.ClassDef):
                symbols.append(_symbol_from_node(path, root, module, node, node.name, "class"))
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and not _is_private_symbol(child.name):
                        symbols.append(_symbol_from_node(path, root, module, child, f"{node.name}.{child.name}", "method"))
    return symbols


def _symbol_from_node(path: Path, root: Path, module: str, node: ast.AST, name: str, kind: str) -> ProductionSymbol:
    return ProductionSymbol(
        file=_rel(path, root),
        module=module,
        name=name,
        kind=kind,
        line_number=getattr(node, "lineno", 1),
        branch_count=sum(1 for child in ast.walk(node) if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match, ast.BoolOp))),
        raises_count=sum(1 for child in ast.walk(node) if isinstance(child, ast.Raise)),
    )


def _collect_test_semantic_signals(root: Path, tests: list[Path]) -> TestSemanticSignals:
    imported_modules: set[str] = set()
    referenced_names: set[str] = set()
    test_files: list[str] = []
    assert_count = 0
    weak_assert_count = 0
    exception_assert_count = 0
    for path in tests:
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (UnicodeDecodeError, SyntaxError):
            continue
        test_files.append(_rel(path, root))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
                    referenced_names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module)
                for alias in node.names:
                    referenced_names.add(alias.asname or alias.name)
                    if node.module:
                        referenced_names.add(f"{node.module}.{alias.name}")
            elif isinstance(node, ast.Name):
                referenced_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                dotted = _call_name(node)
                if dotted:
                    referenced_names.add(dotted)
                    referenced_names.add(node.attr)
            elif isinstance(node, ast.Assert):
                assert_count += 1
                if _is_weak_assert(node.test):
                    weak_assert_count += 1
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in {"pytest.raises", "unittest.TestCase.assertRaises"} or name.endswith(".assertRaises"):
                    exception_assert_count += 1
                if any(part.startswith("assert") for part in name.split(".")):
                    assert_count += 1
    return TestSemanticSignals(
        test_files=tuple(sorted(test_files)),
        imported_modules=frozenset(imported_modules),
        referenced_names=frozenset(referenced_names),
        assert_count=assert_count,
        weak_assert_count=weak_assert_count,
        exception_assert_count=exception_assert_count,
    )


def _symbol_is_referenced(symbol: ProductionSymbol, signals: TestSemanticSignals) -> bool:
    names = signals.referenced_names
    if symbol.qualified_name in names or symbol.name in names:
        return True
    if "." in symbol.name and symbol.name.split(".")[-1] in names and (symbol.module in signals.imported_modules or symbol.module.split(".")[-1] in names):
        return True
    return False


def _discover_python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if not _is_ignored(path))


def _is_test_path(path: Path, root: Path) -> bool:
    rel_parts = path.resolve().relative_to(root.resolve()).parts if path.resolve().is_relative_to(root.resolve()) else path.parts
    return "tests" in rel_parts or path.name.startswith("test_") or path.name.endswith("_test.py")


def _module_name(path: Path, root: Path) -> str:
    rel = path.resolve().relative_to(root.resolve()).with_suffix("")
    parts = [part for part in rel.parts if part != "__init__"]
    return ".".join(parts)


def _is_private_symbol(name: str) -> bool:
    return name.startswith("_") or ".__" in name


def _is_weak_assert(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return bool(node.value) is True
    if isinstance(node, ast.Compare):
        left = node.left
        comparators = node.comparators
        if len(comparators) == 1 and isinstance(left, ast.Constant) and isinstance(comparators[0], ast.Constant):
            return True
    return False

def _run_pytest(root: Path, *, timeout: int, extra_args: tuple[str, ...], disable_plugin_autoload: bool) -> PytestRunSummary:
    import time

    command = (sys.executable, "-m", "pytest", "-q", *extra_args)
    env = os.environ.copy()
    if disable_plugin_autoload:
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
        duration = time.monotonic() - started
        return PytestRunSummary(
            returncode=completed.returncode,
            timed_out=False,
            duration_seconds=round(duration, 3),
            counts=_parse_pytest_counts(completed.stdout + "\n" + completed.stderr),
            command=command,
            stdout_tail=_tail(completed.stdout),
            stderr_tail=_tail(completed.stderr),
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        return PytestRunSummary(
            returncode=124,
            timed_out=True,
            duration_seconds=round(duration, 3),
            counts=_parse_pytest_counts(stdout + "\n" + stderr),
            command=command,
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
        )


def _parse_pytest_counts(text: str) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "errors": 0, "warnings": 0}
    for match in SUMMARY_RE.finditer(text):
        kind = match.group("kind")
        key = "errors" if kind.startswith("error") else kind
        counts[key] = counts.get(key, 0) + int(match.group("count"))
    return counts


def _issues_from_run(root: Path, summary: PytestRunSummary) -> list[Issue]:
    issues: list[Issue] = []
    evidence = {"pytest": summary.to_dict()}
    if summary.timed_out:
        issues.append(Issue(
            file=str(root),
            category="PYTEST001: pytest timeout",
            severity=Severity.CRITICAL,
            detector="pytest_audit",
            description=f"pytest did not finish before timeout ({summary.duration_seconds}s).",
            recommendation="Fix hangs/flaky waits or increase the explicit timeout with justification.",
            confidence="high",
            evidence=evidence,
        ))
    elif summary.returncode != 0:
        issues.append(Issue(
            file=str(root),
            category="PYTEST002: pytest failed",
            severity=Severity.CRITICAL,
            detector="pytest_audit",
            description=f"pytest exited with code {summary.returncode}.",
            recommendation="Fix failing tests before treating the project as release-ready.",
            confidence="high",
            evidence=evidence,
        ))
    if summary.counts.get("xpassed", 0):
        issues.append(Issue(
            file=str(root),
            category="PYTEST003: unexpected passing xfail",
            severity=Severity.HIGH,
            detector="pytest_audit",
            description=f"pytest reported {summary.counts['xpassed']} XPASS tests.",
            recommendation="Remove stale xfail markers or turn the test into a normal required test.",
            confidence="high",
            evidence=evidence,
        ))
    return issues


def _static_test_audit(root: Path) -> list[Issue]:
    tests = _discover_test_files(root)
    issues: list[Issue] = []
    if not tests:
        return [Issue(
            file=str(root),
            category="PYTEST010: no test files discovered",
            severity=Severity.HIGH,
            detector="pytest_audit",
            description="No pytest-style test files were discovered.",
            recommendation="Add tests/test_*.py or *_test.py files, or pass pytest args to the runner deliberately.",
            confidence="high",
        )]
    for path in tests:
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (UnicodeDecodeError, SyntaxError) as exc:
            issues.append(Issue(file=_rel(path, root), category="PYTEST011: unreadable test file", severity=Severity.HIGH, detector="pytest_audit", description=str(exc), recommendation="Fix test file syntax/encoding.", confidence="high"))
            continue
        helper_assertions = {
            n.name
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not n.name.startswith("test")
            and _has_meaningful_assertion(n)
        }
        test_nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test")]
        if not test_nodes and _only_imports_and_constants(tree):
            issues.append(Issue(
                file=_rel(path, root),
                category="PYTEST012: import-only test file",
                severity=Severity.MEDIUM,
                detector="pytest_audit",
                description="Test file imports code but defines no test functions/classes.",
                recommendation="Add behavior assertions or remove the decorative/import-only file.",
                confidence="high",
            ))
        for node in test_nodes:
            location = f"{node.name}:{node.lineno}"
            for issue in _audit_test_function(path, root, node, location, helper_assertions):
                issues.append(issue)
    return issues


def _audit_test_function(path: Path, root: Path, node: ast.FunctionDef | ast.AsyncFunctionDef, location: str, helper_assertions: set[str] | None = None) -> list[Issue]:
    issues: list[Issue] = []
    for marker in _pytest_markers(node):
        if marker["name"] in {"skip", "skipif", "xfail"} and not marker["has_reason"]:
            issues.append(Issue(
                file=_rel(path, root),
                category="PYTEST020: skip/xfail without reason",
                severity=Severity.HIGH,
                detector="pytest_audit",
                description=f"{node.name} uses pytest.mark.{marker['name']} without an explicit reason=... contract.",
                recommendation="Add a precise reason and expiry/issue reference, or remove the marker.",
                location=location,
                line_number=node.lineno,
                confidence="high",
                evidence={"test": node.name, "marker": marker["name"]},
            ))
    if not _has_meaningful_assertion(node) and not _calls_assertive_helper(node, helper_assertions or set()):
        issues.append(Issue(
            file=_rel(path, root),
            category="PYTEST021: test without assertion",
            severity=Severity.MEDIUM,
            detector="pytest_audit",
            description=f"{node.name} has no assert, pytest.raises, pytest.fail, or unittest-style assertion call.",
            recommendation="Add an explicit behavioral assertion so the test cannot pass decoratively.",
            location=location,
            line_number=node.lineno,
            confidence="medium",
            evidence={"test": node.name},
        ))
    for child in ast.walk(node):
        if isinstance(child, ast.Try) and any(_broad_except(handler) for handler in child.handlers):
            issues.append(Issue(
                file=_rel(path, root),
                category="PYTEST022: broad exception swallowing in test",
                severity=Severity.HIGH,
                detector="pytest_audit",
                description=f"{node.name} catches a broad exception; this can hide real failures.",
                recommendation="Use pytest.raises for expected exceptions or catch a precise exception and assert on it.",
                location=f"{node.name}:{getattr(child, 'lineno', node.lineno)}",
                line_number=getattr(child, "lineno", node.lineno),
                confidence="high",
                evidence={"test": node.name},
            ))
    return issues


def _calls_assertive_helper(node: ast.FunctionDef | ast.AsyncFunctionDef, helper_assertions: set[str]) -> bool:
    if not helper_assertions:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id in helper_assertions:
            return True
    return False


def _pytest_markers(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, Any]]:
    markers: list[dict[str, Any]] = []
    for deco in node.decorator_list:
        call = deco if isinstance(deco, ast.Call) else None
        target = call.func if call else deco
        name = _marker_name(target)
        if not name:
            continue
        has_reason = False
        if call:
            has_reason = any(kw.arg == "reason" and _non_empty_literal(kw.value) for kw in call.keywords)
            has_reason = has_reason or any(_non_empty_literal(arg) for arg in call.args)
        markers.append({"name": name, "has_reason": has_reason})
    return markers


def _marker_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    dotted = ".".join(reversed(parts))
    for prefix in ("pytest.mark.", "mark."):
        if dotted.startswith(prefix):
            return dotted[len(prefix):].split(".")[0]
    return None


def _non_empty_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(node.value.strip())


def _has_meaningful_assertion(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        if isinstance(child, ast.Call):
            name = _call_name(child.func)
            if name in {"pytest.raises", "pytest.fail", "unittest.mock.ANY"}:
                return True
            if name.endswith(".assert_called_once") or name.endswith(".assert_called_once_with") or name.endswith(".assert_called_with"):
                return True
            if any(part.startswith("assert") for part in name.split(".")):
                return True
    return False


def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _broad_except(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name) and handler.type.id in {"Exception", "BaseException"}:
        return True
    return False


def _only_imports_and_constants(tree: ast.Module) -> bool:
    meaningful = [node for node in tree.body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))]
    return bool(meaningful) and all(isinstance(node, (ast.Import, ast.ImportFrom)) for node in meaningful)


def _discover_test_files(root: Path) -> list[Path]:
    files: set[Path] = set()
    candidates = [root / "tests", root]
    for base in candidates:
        if not base.exists():
            continue
        for pattern in TEST_FILE_PATTERNS:
            for path in base.rglob(pattern):
                if _is_ignored(path):
                    continue
                files.add(path)
    return sorted(files)


def _is_ignored(path: Path) -> bool:
    ignored = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "dist", "build"}
    return any(part in ignored for part in path.parts)


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _tail(text: str, *, max_chars: int = 5000) -> str:
    return text[-max_chars:] if len(text) > max_chars else text
