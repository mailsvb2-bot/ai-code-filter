from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.integrity import audit_file_integrity, generate_manifest, parse_manifest, verify_manifest, write_manifest
from ai_code_filter.release.audit import audit_release


def test_manifest_generation_and_verification(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("hello\n", encoding="utf-8")
    manifest = write_manifest(root)
    entries = parse_manifest(manifest)
    assert len(entries) == 1
    report = verify_manifest(root, manifest)
    assert report.summary()["TOTAL"] == 0


def test_verify_manifest_detects_tampering(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("hello\n", encoding="utf-8")
    manifest = write_manifest(root)
    target.write_text("changed\n", encoding="utf-8")
    report = verify_manifest(root, manifest)
    cats = {issue.category.split(":", 1)[0] for issue in report.issues}
    assert "MANIFEST003" in cats
    assert "MANIFEST004" in cats


def test_integrity_detects_invalid_structured_files_and_nul_bytes(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "bad.json").write_text('{"broken": ', encoding="utf-8")
    (root / "bad.toml").write_text("[broken\n", encoding="utf-8")
    (root / "bad.xml").write_text("<root>", encoding="utf-8")
    (root / "bad.txt").write_bytes(b"abc\x00def")
    report = audit_file_integrity(root)
    cats = {issue.category.split(":", 1)[0] for issue in report.issues}
    assert {"STRUCT001", "STRUCT002", "STRUCT003", "CORRUPT001"}.issubset(cats)


def test_integrity_detects_broken_markdown_link(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("[missing](docs/missing.md)\n", encoding="utf-8")
    report = audit_file_integrity(root)
    assert any(issue.category.startswith("LINK002") for issue in report.issues)


def test_integrity_detects_case_collisions(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "Readme.md").write_text("a\n", encoding="utf-8")
    (root / "README.md").write_text("b\n", encoding="utf-8")
    report = audit_file_integrity(root)
    assert any(issue.category.startswith("PATH001") for issue in report.issues)


def test_release_audit_detects_empty_critical_file(tmp_path: Path):
    root = tmp_path / "ai_code_filter_refactored_v18"
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "README.md").write_text("# Project v0.18\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("", encoding="utf-8")
    (root / "ai_filter.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text('__version__ = "0.18.0"\n', encoding="utf-8")
    report = audit_release(root, run_cli_matrix=False)
    assert any(issue.category.startswith("EMPTY001") for issue in report.issues)


def test_cli_generate_and_verify_manifest(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("hello\n", encoding="utf-8")
    manifest = tmp_path / "nested" / "MANIFEST.sha256"
    assert main(["generate-manifest", str(root), "--output", str(manifest)]) == 0
    out = tmp_path / "nested" / "verify.json"
    assert main(["verify-manifest", str(root), "--manifest", str(manifest), "--output", str(out), "--ci"]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["TOTAL"] == 0


def test_release_audit_rejects_bad_zip_crc_like_invalid_archive(tmp_path: Path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"not a zip")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE003") for issue in report.issues)
