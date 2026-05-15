from __future__ import annotations

import ast
import hashlib
import re

from .base import Analyzer
from ..models import FilePayload, Issue, Severity


class PythonContractFingerprint:
    def __init__(self, code: str) -> None:
        self.code = code
        try:
            self.tree = ast.parse(code)
        except SyntaxError:
            self.tree = None

    def function_signatures(self) -> list[dict]:
        if not self.tree:
            return []
        signatures: list[dict] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = [(arg.arg, ast.unparse(arg.annotation) if arg.annotation else None) for arg in node.args.args]
            kwonly = [(arg.arg, ast.unparse(arg.annotation) if arg.annotation else None) for arg in node.args.kwonlyargs]
            ret = ast.unparse(node.returns) if node.returns else None
            signatures.append({"name": node.name, "args": args, "kwonly": kwonly, "returns": ret, "async": isinstance(node, ast.AsyncFunctionDef)})
        return signatures

    def safety_checks(self) -> list[str]:
        patterns = {
            "null_check": r"if\s+\w+\s+(?:is\s+not\s+None|!=\s*None)",
            "range_check": r"if\s+\d+\s*[<>=]+\s*\w+\s*[<>=]+\s*\d+",
            "input_validation": r"(?:validate|sanitize|check)\s*\(",
            "error_handling": r"try\s*:",
            "auth_check": r"(?:is_admin|is_authorized|has_permission|check_auth)",
            "type_check": r"isinstance\s*\(",
        }
        return [name for name, pattern in patterns.items() if re.search(pattern, self.code, re.IGNORECASE)]

    def fingerprint(self) -> dict:
        raw = str(self.function_signatures()) + str(sorted(self.safety_checks()))
        return {
            "signatures": self.function_signatures(),
            "safety_checks": self.safety_checks(),
            "interface_hash": hashlib.sha256(raw.encode()).hexdigest(),
        }


def compare_contracts(old_code: str, new_code: str, file: str = "") -> list[Issue]:
    old_fp = PythonContractFingerprint(old_code).fingerprint()
    new_fp = PythonContractFingerprint(new_code).fingerprint()
    issues: list[Issue] = []
    old_sigs = {signature["name"]: signature for signature in old_fp["signatures"]}
    new_sigs = {signature["name"]: signature for signature in new_fp["signatures"]}
    for name, old_sig in old_sigs.items():
        if name not in new_sigs:
            issues.append(Issue(file=file, category="Contract", severity=Severity.CRITICAL, detector="contract", description=f"Function removed: {name}", recommendation="Restore the function or document and migrate all callers."))
            continue
        new_sig = new_sigs[name]
        if old_sig != new_sig:
            issues.append(Issue(file=file, category="Contract", severity=Severity.HIGH, detector="contract", description=f"Signature changed for {name}", recommendation="Keep backward compatibility or update all call sites."))
    removed_checks = set(old_fp["safety_checks"]) - set(new_fp["safety_checks"])
    if removed_checks:
        issues.append(Issue(file=file, category="Contract", severity=Severity.CRITICAL, detector="contract", description=f"Safety checks removed: {', '.join(sorted(removed_checks))}", recommendation="Restore removed safety checks or justify the migration."))
    return issues


class PythonContractAnalyzer(Analyzer):
    name = "python_contract"

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        if PythonContractFingerprint(payload.content).tree is None:
            return [Issue(file=payload.relative_path, category="Syntax", severity=Severity.CRITICAL, detector=self.name, description="Python syntax parsing failed.", recommendation="Fix syntax before deeper analysis.")]
        return []
