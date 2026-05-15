from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

_PACKAGE_IMPORT_ALIASES = {
    "pyyaml": "yaml",
    "python-dotenv": "dotenv",
    "beautifulsoup4": "bs4",
    "opencv-python": "cv2",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "google-cloud-storage": "google",
}
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


@dataclass(frozen=True)
class DependencyManifest:
    project_root: Path
    python_dependencies: tuple[str, ...] = ()
    javascript_dependencies: tuple[str, ...] = ()
    lockfiles: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()

    @property
    def python_import_roots(self) -> tuple[str, ...]:
        roots = {_dependency_to_import_root(dep) for dep in self.python_dependencies}
        return tuple(sorted(root for root in roots if root))

    @property
    def javascript_package_roots(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.javascript_dependencies)))


def _dependency_to_import_root(requirement: str) -> str:
    name = requirement.strip()
    if not name or name.startswith(("#", "-")):
        return ""
    match = _REQ_NAME_RE.match(name)
    if not match:
        return ""
    package = match.group(1).lower().replace("_", "-")
    mapped = _PACKAGE_IMPORT_ALIASES.get(package, package)
    return mapped.replace("-", "_").split(".")[0]


def _clean_requirement_line(line: str) -> str:
    line = line.split("#", 1)[0].strip()
    if not line:
        return ""
    lowered = line.lower()
    skip_prefixes = ("-r ", "--requirement", "-c ", "--constraint", "-e ", "--editable", "-f ", "--find-links", "--index-url", "--extra-index-url", "--trusted-host", "--pre", "--upgrade")
    if lowered.startswith(skip_prefixes) or lowered.startswith("git+") or lowered.startswith("http://") or lowered.startswith("https://"):
        return ""
    return line


def _normalize_unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = value.strip()
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return tuple(out)


class DependencyResolver:
    """Reads dependency manifests without importing project code or third-party SDKs."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()

    def resolve(self) -> DependencyManifest:
        py_deps: list[str] = []
        js_deps: list[str] = []
        lockfiles: list[str] = []
        sources: list[str] = []

        pyproject = self.project_root / "pyproject.toml"
        if pyproject.exists():
            sources.append("pyproject.toml")
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
                project = data.get("project", {})
                py_deps.extend(project.get("dependencies", []) or [])
                optional = project.get("optional-dependencies", {}) or {}
                for group in optional.values():
                    py_deps.extend(group or [])
                poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
                py_deps.extend(name for name in poetry_deps if name.lower() != "python")
            except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
                sources.append("pyproject.toml:unreadable")

        for req_name in ("requirements.txt", "requirements-dev.txt", "dev-requirements.txt"):
            req = self.project_root / req_name
            if req.exists():
                sources.append(req_name)
                for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
                    cleaned = _clean_requirement_line(line)
                    if cleaned:
                        py_deps.append(cleaned)

        package_json = self.project_root / "package.json"
        if package_json.exists():
            sources.append("package.json")
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
                for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    js_deps.extend((data.get(key) or {}).keys())
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                sources.append("package.json:unreadable")

        for name in ("poetry.lock", "Pipfile.lock", "requirements.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            if (self.project_root / name).exists():
                lockfiles.append(name)

        return DependencyManifest(
            project_root=self.project_root,
            python_dependencies=_normalize_unique(py_deps),
            javascript_dependencies=_normalize_unique(js_deps),
            lockfiles=tuple(sorted(lockfiles)),
            sources=tuple(sorted(set(sources))),
        )
