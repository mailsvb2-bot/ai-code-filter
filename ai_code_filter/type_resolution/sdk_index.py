from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .dependencies import DependencyManifest


@dataclass(frozen=True)
class SDKPackageIndex:
    root: str
    available: bool
    imported: bool
    public_attributes: tuple[str, ...] = ()
    callables: tuple[str, ...] = ()
    class_methods: dict[str, tuple[str, ...]] | None = None
    error: str | None = None

    def has_attribute(self, name: str) -> bool:
        return name in self.public_attributes or name in self.callables or name in (self.class_methods or {})

    def has_method(self, class_name: str, method_name: str) -> bool:
        methods = self.class_methods or {}
        return method_name in methods.get(class_name, ())


@dataclass(frozen=True)
class SDKIndex:
    packages: dict[str, SDKPackageIndex]

    def package(self, root: str) -> SDKPackageIndex | None:
        return self.packages.get(root)

    def known_roots(self) -> set[str]:
        return set(self.packages)

    def known_call_names(self) -> set[str]:
        names: set[str] = set()
        for pkg in self.packages.values():
            names.update(pkg.callables)
            for methods in (pkg.class_methods or {}).values():
                names.update(methods)
        return names

    def to_dict(self) -> dict:
        return {"packages": {root: asdict(pkg) for root, pkg in sorted(self.packages.items())}}


def _safe_public_names(obj: object, limit: int) -> tuple[str, ...]:
    try:
        names = [name for name in dir(obj) if not name.startswith("_")]
    except Exception:
        return ()
    return tuple(sorted(names)[:limit])


def _stdlib_roots() -> set[str]:
    return set(getattr(sys, "stdlib_module_names", set())) | {"xml", "importlib", "json", "pathlib", "datetime", "subprocess"}


def build_sdk_index(
    manifest: DependencyManifest,
    extra_import_roots: Iterable[str] = (),
    *,
    import_packages: bool = False,
    import_allowlist: Iterable[str] | None = None,
    max_packages: int = 80,
    max_members_per_package: int = 500,
) -> SDKIndex:
    roots = sorted({*manifest.python_import_roots, *extra_import_roots})[:max_packages]
    allowed = {r.split(".", 1)[0] for r in (import_allowlist or manifest.python_import_roots)} | _stdlib_roots()
    packages: dict[str, SDKPackageIndex] = {}
    for root in roots:
        root_key = root.split(".", 1)[0]
        try:
            spec = importlib.util.find_spec(root)
        except (ImportError, ModuleNotFoundError, ValueError) as exc:
            packages[root] = SDKPackageIndex(root=root, available=False, imported=False, error=f"{type(exc).__name__}: {exc}")
            continue
        if spec is None:
            packages[root] = SDKPackageIndex(root=root, available=False, imported=False, error="module spec not found")
            continue
        should_import = import_packages and root_key in allowed
        if not should_import:
            packages[root] = SDKPackageIndex(root=root, available=True, imported=False)
            continue
        try:
            module = importlib.import_module(root)
            public = _safe_public_names(module, max_members_per_package)
            callables: list[str] = []
            class_methods: dict[str, tuple[str, ...]] = {}
            for name in public:
                try:
                    value = getattr(module, name)
                except Exception:
                    continue
                if callable(value):
                    callables.append(name)
                if inspect.isclass(value):
                    methods = []
                    for method_name in _safe_public_names(value, 200):
                        try:
                            method = getattr(value, method_name)
                        except Exception:
                            continue
                        if callable(method):
                            methods.append(method_name)
                    class_methods[name] = tuple(sorted(methods))
            packages[root] = SDKPackageIndex(root=root, available=True, imported=True, public_attributes=public, callables=tuple(sorted(callables)), class_methods=class_methods)
        except Exception as exc:
            packages[root] = SDKPackageIndex(root=root, available=True, imported=False, error=f"{type(exc).__name__}: {exc}")
    return SDKIndex(packages=packages)


def write_sdk_index(index: SDKIndex, path: Path | str | None) -> None:
    """Write an SDK index JSON file; return None when no output path is requested."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(index.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
