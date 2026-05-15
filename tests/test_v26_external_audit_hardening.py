from __future__ import annotations

import json
import subprocess
import sys
import zipfile
import unicodedata
from pathlib import Path

import pytest

from ai_code_filter.integrity import audit_file_integrity, parse_manifest
from ai_code_filter.release.audit import audit_release

HEX = "a" * 64


def _manifest(tmp_path: Path, rel: str, size: str = "1") -> Path:
    path = tmp_path / "MANIFEST.sha256"
    path.write_text(f"{HEX}  {rel}  size={size}\n", encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "rel",
    [
        "~/evil.txt",
        "COM¹.txt",
        "safe／evil.txt",
        "safe∕evil.txt",
        "safe⁄evil.txt",
    ],
)
def test_manifest_rejects_home_unicode_separator_and_superscript_devices(tmp_path: Path, rel: str) -> None:
    with pytest.raises(ValueError):
        parse_manifest(_manifest(tmp_path, rel))


def test_generate_manifest_rejects_missing_root(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "ai_filter.py", "generate-manifest", str(tmp_path / "missing"), "--output", str(tmp_path / "out.sha256")],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.returncode != 0
    assert "does not exist" in proc.stderr


def test_tree_integrity_rejects_unicode_separator_and_superscript_devices(tmp_path: Path) -> None:
    for rel in ["COM¹.txt", "safe／evil.txt", "safe∕evil.txt", "safe⁄evil.txt", "~evil.txt"]:
        (tmp_path / rel).write_text("x\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    cats = {issue.category.split(":", 1)[0] for issue in report.issues}
    assert "PATH003" in cats


def test_tree_integrity_rejects_unicode_normalization_collision(tmp_path: Path) -> None:
    (tmp_path / "café.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / (unicodedata.normalize("NFD", "café") + ".txt")).write_text("b\n", encoding="utf-8")
    # Distinct byte-level names can still collide after Unicode normalization on common filesystems.
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("PATH004") for issue in report.issues)


def test_json_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("STRUCT001") for issue in report.issues)


def test_xml_doctype_is_rejected_even_when_parser_accepts_document(tmp_path: Path) -> None:
    (tmp_path / "x.xml").write_text('<!DOCTYPE x><x/>\n', encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("STRUCT006") for issue in report.issues)


def test_markdown_html_href_and_src_links_are_checked(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text('<a href="missing.md">x</a>\n<img src="missing.png">\n', encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert sum(1 for issue in report.issues if issue.category.startswith("LINKHTML002")) == 2


def test_zip_directory_entries_are_validated_for_unsafe_names_and_duplicates(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/", "")
        zf.writestr("pkg/../evil/", "")
        zf.writestr("pkg/DOCS/", "")
        zf.writestr("pkg/docs/", "")
        zf.writestr("pkg/docs/", "")
        zf.writestr("pkg/README.md", "# ok\n")
    report = audit_release(archive, run_cli_matrix=False)
    cats = [issue.category.split(":", 1)[0] for issue in report.issues]
    assert "ARCHIVE006" in cats
    assert "ARCHIVE011" in cats
    assert "ARCHIVE014" in cats


def test_zip_unicode_normalization_duplicate_members_are_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "bad_norm.zip"
    nfd = unicodedata.normalize("NFD", "café.txt")
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/café.txt", "a")
        zf.writestr(f"pkg/{nfd}", "b")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE015") for issue in report.issues)
