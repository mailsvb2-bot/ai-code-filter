from __future__ import annotations

import json
import os
import stat
import zipfile
from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.models import Severity
from ai_code_filter.release.audit import audit_release
from ai_code_filter.type_resolution.dependencies import DependencyResolver
from ai_code_filter.type_resolution.sdk_index import build_sdk_index


def test_requirements_editable_and_tool_options_are_not_dependencies(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("""
-e .
--extra-index-url https://example.invalid/simple
-r other.txt
requests>=2; python_version>='3.10'
python-dotenv>=1
""", encoding="utf-8")
    manifest = DependencyResolver(tmp_path).resolve()
    assert "-e ." not in manifest.python_dependencies
    assert "requests" in manifest.python_import_roots
    assert "dotenv" in manifest.python_import_roots


def test_safe_sdk_index_does_not_import_project_local_modules(tmp_path: Path):
    (tmp_path / "localmod.py").write_text("raise RuntimeError('should not be imported')\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\ndependencies=[]\n", encoding="utf-8")
    code = main(["analyze", str(tmp_path), "--no-ai", "--no-drift", "--sdk-index", "--unknown-call-check"])
    assert code == 0


def test_import_packages_only_imports_allowlisted_dependencies(tmp_path: Path):
    (tmp_path / "localmod.py").write_text("raise RuntimeError('should not be imported')\n", encoding="utf-8")
    manifest = DependencyResolver(tmp_path).resolve()
    index = build_sdk_index(manifest, extra_import_roots={"localmod", "json"}, import_packages=True, import_allowlist=manifest.python_import_roots)
    assert index.package("localmod") is not None
    assert index.package("localmod").imported is False
    assert index.package("json").imported is True


def _minimal_release(root: Path, version: str = "0.17.0") -> None:
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "ai_code_filter" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "ai_filter.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "README.md").write_text("# Project v0.17\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(f"[project]\nname='x'\nversion='{version}'\n[project.scripts]\nai-code-filter='ai_code_filter.cli:main'\n", encoding="utf-8")


def test_release_audit_rejects_top_level_files_outside_root(tmp_path: Path):
    root = tmp_path / "pkg_v17"
    _minimal_release(root)
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(root / "pyproject.toml", "pkg_v17/pyproject.toml")
        zf.writestr("README.md", "stray")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE008") for issue in report.issues)


def test_release_audit_rejects_zip_traversal(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg_v17/pyproject.toml", "[project]\nname='x'\nversion='0.17.0'\n")
        zf.writestr("../evil.py", "print('evil')")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE006") for issue in report.issues)


def test_release_audit_rejects_zip_symlink(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    info = zipfile.ZipInfo("pkg_v17/link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg_v17/pyproject.toml", "[project]\nname='x'\nversion='0.17.0'\n")
        zf.writestr(info, "target")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE007") for issue in report.issues)


def test_release_audit_checks_python_syntax(tmp_path: Path):
    root = tmp_path / "pkg_v17"
    _minimal_release(root)
    (root / "ai_code_filter" / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    report = audit_release(root, run_cli_matrix=False)
    assert any(issue.category.startswith("PYCOMPILE001") for issue in report.issues)


def test_release_audit_requires_script_and_layout(tmp_path: Path):
    root = tmp_path / "pkg_v17"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.17.0'\n", encoding="utf-8")
    report = audit_release(root, run_cli_matrix=False)
    cats = {issue.category.split(':',1)[0] for issue in report.issues}
    assert "LAYOUT001" in cats
    assert "REL005" in cats
