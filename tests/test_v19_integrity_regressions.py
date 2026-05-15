from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path

import pytest

from ai_code_filter.integrity import audit_file_integrity, parse_manifest, verify_manifest, write_manifest
from ai_code_filter.release.audit import audit_release


def make_min_project(root: Path, version: str = "0.25.0") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "ai_code_filter").mkdir()
    (root / "tests").mkdir()
    (root / "docs").mkdir()
    (root / "ai_filter.py").write_text("from ai_code_filter.cli import main\n", encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "README.md").write_text(f"# Project v0.25\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f"[project]\nname='ai-code-filter'\nversion='{version}'\n[project.scripts]\nai-code-filter='ai_code_filter.cli:main'\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_smoke.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    write_manifest(root)
    return root


def categories(report):
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def test_release_audit_verifies_embedded_manifest(tmp_path):
    root = make_min_project(tmp_path / "ai_code_filter_refactored_v25")
    (root / "README.md").write_text("# corrupted after manifest\n", encoding="utf-8")
    report = audit_release(root, run_cli_matrix=False)
    assert "MANIFEST003" in categories(report) or "MANIFEST004" in categories(report)


def test_release_audit_requires_embedded_manifest(tmp_path):
    root = make_min_project(tmp_path / "ai_code_filter_refactored_v25")
    (root / "MANIFEST.sha256").unlink()
    report = audit_release(root, run_cli_matrix=False)
    assert "MANIFEST006" in categories(report)


def test_manifest_rejects_duplicate_negative_and_unsafe_paths(tmp_path):
    manifest = tmp_path / "MANIFEST.sha256"
    digest = "a" * 64
    bads = [
        f"{digest}  a.txt  size=1\n{digest}  a.txt  size=1\n",
        f"{digest}  a.txt  size=-1\n",
        f"{digest}  ../a.txt  size=1\n",
        f"{digest}  /a.txt  size=1\n",
        f"{digest}  a\\\\b.txt  size=1\n",
        f"{digest}    size=1\n",
    ]
    for text in bads:
        manifest.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError):
            parse_manifest(manifest)


def test_verify_manifest_missing_root_is_reported(tmp_path):
    manifest = tmp_path / "MANIFEST.sha256"
    manifest.write_text("a" * 64 + "  x.txt  size=1\n", encoding="utf-8")
    report = verify_manifest(tmp_path / "missing", manifest)
    assert "MANIFEST000" in categories(report)


def test_integrity_detects_symlink_and_broken_symlink(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "target.txt").write_text("ok\n", encoding="utf-8")
    os.symlink(root / "target.txt", root / "link.txt")
    os.symlink(root / "missing.txt", root / "broken.txt")
    report = audit_file_integrity(root)
    assert "PATH002" in categories(report)
    assert sum(1 for issue in report.issues if issue.category.startswith("PATH002")) >= 2


def test_integrity_detects_cr_only_and_bom(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "legacy.md").write_bytes(b"a\rb\r")
    (root / "bom.json").write_bytes(b"\xef\xbb\xbf{}\n")
    report = audit_file_integrity(root)
    cats = categories(report)
    assert "LINES002" in cats
    assert "ENCODING003" in cats


def test_integrity_checks_markdown_reference_links(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "README.md").write_text("See [missing][m].\n\n[m]: docs/missing.md\n", encoding="utf-8")
    report = audit_file_integrity(root)
    assert "LINKREF002" in categories(report)


def test_release_audit_rejects_bad_zip_names_and_duplicates(tmp_path):
    zip_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("pkg_v25/pyproject.toml", "[project]\nname='x'\nversion='0.25.0'\n")
        zf.writestr("pkg_v25/pyproject.toml", "[project]\nname='x'\nversion='0.25.0'\n")
        zf.writestr("C:/evil.txt", "bad")
        zf.writestr("pkg_v25\\evil.txt", "bad")
    report = audit_release(zip_path, run_cli_matrix=False)
    cats = categories(report)
    assert "ARCHIVE011" in cats
    assert "ARCHIVE006" in cats


def test_release_audit_flags_zip_bomb_like_member(tmp_path):
    zip_path = tmp_path / "bomb.zip"
    payload = b"0" * (11 * 1024 * 1024)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg_v25/huge.txt", payload, compress_type=zipfile.ZIP_DEFLATED)
    report = audit_release(zip_path, run_cli_matrix=False)
    assert "ARCHIVE012" in categories(report) or "ARCHIVE013" in categories(report)


def test_pycompile_does_not_create_pycache(tmp_path):
    root = make_min_project(tmp_path / "ai_code_filter_refactored_v25")
    audit_release(root, run_cli_matrix=False)
    assert not list(root.rglob("__pycache__"))


def test_release_audit_cli_does_not_dirty_current_tree_with_pycache(tmp_path):
    from ai_code_filter.cli import main
    root = make_min_project(tmp_path / "ai_code_filter_refactored_v25")
    out = tmp_path / "release.json"
    code = main(["release-audit", str(root), "--skip-cli-matrix", "--output", str(out)])
    assert code == 0
    assert not list(root.rglob("__pycache__"))
