from __future__ import annotations

import json
import unicodedata
import zipfile
from pathlib import Path

import pytest

from ai_code_filter.integrity import MANIFEST_NAME, audit_file_integrity, parse_manifest, generate_manifest
from ai_code_filter.release.audit import audit_release

DIGEST = "a" * 64


def _manifest(tmp_path: Path, rel: str):
    path = tmp_path / MANIFEST_NAME
    path.write_text(f"{DIGEST}  {rel}  size=1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_manifest(path)


@pytest.mark.parametrize(
    "rel",
    [
        "pkg/ evil.txt",
        "pkg/\u00a0evil.txt",
        "pkg/~/evil.txt",
        "pkg/．．/evil.txt",
        "pkg/evil：name.txt",
        "pkg/abc\ufdd0.txt",
    ],
)
def test_manifest_rejects_nested_unicode_and_whitespace_path_bypasses(tmp_path: Path, rel: str):
    _manifest(tmp_path, rel)


def test_manifest_rejects_nfkc_collision(tmp_path: Path):
    path = tmp_path / MANIFEST_NAME
    path.write_text(
        f"{DIGEST}  pkg/A.txt  size=1\n{DIGEST}  pkg/Ａ.txt  size=1\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        parse_manifest(path)


@pytest.mark.parametrize(
    "rel",
    [
        "pkg/ evil.txt",
        "pkg/\u00a0evil.txt",
        "pkg/~/evil.txt",
        "pkg/．．/evil.txt",
        "pkg/evil：name.txt",
        "pkg/abc\ufdd0.txt",
    ],
)
def test_tree_integrity_rejects_nested_unicode_and_whitespace_path_bypasses(tmp_path: Path, rel: str):
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("PATH003") for issue in report.issues)


def test_tree_integrity_rejects_nfkc_collision(tmp_path: Path):
    (tmp_path / "A.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "Ａ.txt").write_text("b\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("PATH004") for issue in report.issues)


def test_generate_manifest_rejects_nfkc_collision(tmp_path: Path):
    (tmp_path / "A.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "Ａ.txt").write_text("b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        generate_manifest(tmp_path)


def test_json_rejects_non_standard_constants(tmp_path: Path):
    (tmp_path / "bad.json").write_text('{"value": NaN}\n', encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("STRUCT001") for issue in report.issues)


def test_yaml_inline_map_duplicate_keys_are_rejected(tmp_path: Path):
    (tmp_path / "bad.yaml").write_text("value: {a: 1, a: 2}\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("STRUCT009") for issue in report.issues)


def test_markdown_unquoted_html_links_are_audited(tmp_path: Path):
    (tmp_path / "README.md").write_text("<a href=missing.md>x</a>\n<img src=missing.png>\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    missing = [issue for issue in report.issues if issue.category.startswith("LINKHTML002")]
    assert len(missing) == 2


@pytest.mark.parametrize(
    "member",
    [
        "pkg/ evil.txt",
        "pkg/\u00a0evil.txt",
        "pkg/~/evil.txt",
        "pkg/．．/evil.txt",
        "pkg/evil：name.txt",
        "pkg/abc\ufdd0.txt",
    ],
)
def test_zip_audit_rejects_nested_unicode_and_whitespace_members(tmp_path: Path, member: str):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(member, "x")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE006") for issue in report.issues)


def test_zip_audit_rejects_nfkc_duplicate_members(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/A.txt", "a")
        zf.writestr("pkg/Ａ.txt", "b")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE015") for issue in report.issues)
