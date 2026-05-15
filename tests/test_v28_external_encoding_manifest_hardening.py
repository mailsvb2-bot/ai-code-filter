from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from ai_code_filter.integrity import audit_file_integrity, generate_manifest, parse_manifest
from ai_code_filter.release.audit import audit_release


def _write_manifest(path: Path, rels: list[str]) -> None:
    lines = []
    for i, rel in enumerate(rels):
        digest = hex(i + 1)[2:].rjust(64, "a")[-64:]
        lines.append(f"{digest}  {rel}  size=1")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    "rel",
    [
        "dir%2Fevil.txt",
        "dir%2fevil.txt",
        "dir%252Fevil.txt",
        "dir%252fevil.txt",
        "dir%5Cevil.txt",
        "dir%255Cevil.txt",
    ],
)
def test_manifest_rejects_percent_encoded_path_separators(tmp_path: Path, rel: str) -> None:
    manifest = tmp_path / "MANIFEST.sha256"
    _write_manifest(manifest, [rel])
    with pytest.raises(ValueError):
        parse_manifest(manifest)


def test_manifest_rejects_casefold_collisions(tmp_path: Path) -> None:
    manifest = tmp_path / "MANIFEST.sha256"
    _write_manifest(manifest, ["README.md", "readme.md"])
    with pytest.raises(ValueError):
        parse_manifest(manifest)


def test_manifest_rejects_unicode_normalization_collisions(tmp_path: Path) -> None:
    manifest = tmp_path / "MANIFEST.sha256"
    _write_manifest(manifest, ["café.txt", "café.txt"])
    with pytest.raises(ValueError):
        parse_manifest(manifest)


def test_generate_manifest_rejects_unsafe_paths(tmp_path: Path) -> None:
    (tmp_path / "dir%2Fevil.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError):
        generate_manifest(tmp_path)


def test_generate_manifest_rejects_casefold_collisions(tmp_path: Path) -> None:
    (tmp_path / "A.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        generate_manifest(tmp_path)


def test_generate_manifest_rejects_unicode_normalization_collisions(tmp_path: Path) -> None:
    (tmp_path / "café.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "café.txt").write_text("b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        generate_manifest(tmp_path)


@pytest.mark.parametrize("name", [".env", ".env.local", "__MACOSX/file", ".idea/workspace.xml", ".vscode/settings.json"])
def test_release_noise_paths_are_flagged(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("HYGIENE002") for issue in report.issues)


def test_yaml_duplicate_keys_are_flagged(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("name: one\nname: two\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("STRUCT007") for issue in report.issues)


def test_ini_duplicate_keys_are_flagged(tmp_path: Path) -> None:
    (tmp_path / "config.ini").write_text("[app]\nkey=1\nkey=2\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("STRUCT008") for issue in report.issues)


def test_markdown_encoded_slash_target_is_unsafe(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("ok\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("[guide](docs%2Fguide.md)\n", encoding="utf-8")
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith("LINK001") for issue in report.issues)


@pytest.mark.parametrize("member", ["pkg/docs%2Fguide.md", "pkg/docs%252Fguide.md", "pkg/docs%5Cguide.md"])
def test_zip_encoded_separator_members_are_unsafe(tmp_path: Path, member: str) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/README.md", "# ok\n")
        zf.writestr(member, "x\n")
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE006") for issue in report.issues)
