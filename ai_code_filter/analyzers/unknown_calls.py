from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass

from .base import Analyzer
from ..models import FilePayload, Issue, Severity
from ..type_resolution.sdk_index import SDKIndex


@dataclass(frozen=True)
class ImportBinding:
    alias: str
    module: str
    imported_name: str | None = None

    @property
    def root(self) -> str:
        return self.module


class UnknownCallValidator(Analyzer):
    """Conservative unresolved-call checker backed by local symbols and optional SDK index.

    It deliberately reports only high-confidence problems. General method calls on arbitrary
    runtime objects are not flagged because they require a full type checker.
    """

    name = "unknown_call_validator"

    def __init__(self, sdk_index: SDKIndex | None = None) -> None:
        self.sdk_index = sdk_index or SDKIndex(packages={})
        self.builtins = set(dir(builtins))

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix != ".py":
            return []
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            return []
        local_defs = self._local_defs(tree)
        imports = self._imports(tree)
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            if isinstance(target, ast.Name):
                name = target.id
                if name in local_defs or name in self.builtins or name in imports:
                    continue
                # Avoid noisy reports for names from star imports, decorators, or framework injection.
                continue
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                binding = imports.get(target.value.id)
                if not binding:
                    continue
                pkg = self.sdk_index.package(binding.module)
                if pkg is None and "." in binding.module:
                    pkg = self.sdk_index.package(binding.module.split(".", 1)[0])
                if pkg and pkg.imported and binding.imported_name is None and not pkg.has_attribute(target.attr):
                    issues.append(Issue(file=payload.relative_path, category="Unknown SDK attribute", severity=Severity.HIGH, detector=self.name, description=f"Imported SDK/module '{binding.module}' has no public attribute '{target.attr}' in the local SDK index.", recommendation="Check the installed SDK version, add a stub/manifest, or fix the called attribute.", location=ast.unparse(target), line_number=getattr(node, "lineno", None)))
        return issues

    def _local_defs(self, tree: ast.AST) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        return names

    def _imports(self, tree: ast.AST) -> dict[str, ImportBinding]:
        imports: dict[str, ImportBinding] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    default_alias = alias.name.split(".")[0]
                    bound_alias = alias.asname or default_alias
                    # Python binds `import package.submodule` to `package`, but
                    # `import package.submodule as alias` binds the alias to the full module.
                    module = alias.name if alias.asname else default_alias
                    imports[bound_alias] = ImportBinding(alias=bound_alias, module=module)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                module = node.module
                for alias in node.names:
                    imports[alias.asname or alias.name] = ImportBinding(alias=alias.asname or alias.name, module=module, imported_name=alias.name)
        return imports
