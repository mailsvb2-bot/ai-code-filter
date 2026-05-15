from pathlib import Path

from ai_code_filter.integrity import MANIFEST_NAME, audit_file_integrity, parse_manifest, verify_manifest, write_manifest
from ai_code_filter.release.audit import audit_release


def _minimal(root: Path, version: str = "0.25.0") -> Path:
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "ai_filter.py").write_text("from ai_code_filter.cli import main\nraise SystemExit(main())\n", encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
    (root / "README.md").write_text("# Project v25\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname="x"\nversion="{version}"\n[project.scripts]\nai-code-filter="ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    write_manifest(root)
    return root


def _codes(report):
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def test_manifest_rejects_windows_drive_and_ambiguous_space_paths(tmp_path):
    """Returns None; raises AssertionError if unsafe manifest paths are accepted."""
    manifest = tmp_path / "MANIFEST.sha256"
    digest = "a" * 64
    manifest.write_text(f"{digest}  C:/evil.txt  size=0\n", encoding="utf-8")
    try:
        parse_manifest(manifest)
    except ValueError as exc:
        assert "Unsafe manifest path" in str(exc)
    else:
        raise AssertionError("Windows drive path was accepted")
    manifest.write_text(f"{digest}  bad  name.txt  size=1\n", encoding="utf-8")
    try:
        parse_manifest(manifest)
    except ValueError as exc:
        assert "Invalid manifest line" in str(exc) or "Unsafe manifest path" in str(exc)
    else:
        raise AssertionError("ambiguous double-space manifest path was accepted")


def test_verify_manifest_rejects_symlink_entries(tmp_path):
    """Returns None when symlinks are unsupported; otherwise validates symlink rejection."""
    root = tmp_path / "root"; root.mkdir()
    outside = tmp_path / "outside.txt"; outside.write_text("secret", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        return
    digest = "a" * 64
    manifest = root / MANIFEST_NAME
    manifest.write_text(f"{digest}  link.txt  size=6\n", encoding="utf-8")
    assert "MANIFEST006" in _codes(verify_manifest(root, manifest))


def test_integrity_flags_repository_and_dependency_noise_dirs(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    for dirname in [".git", ".venv", "node_modules", "dist", "build"]:
        path = root / dirname
        path.mkdir()
        (path / "junk.txt").write_text("junk\n", encoding="utf-8")
    codes = _codes(audit_file_integrity(root))
    assert "HYGIENE002" in codes


def test_markdown_rejects_windows_and_backslash_links_and_allows_reference_space(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    (root / "docs").mkdir()
    (root / "docs" / "a file.md").write_text("ok\n", encoding="utf-8")
    (root / "README.md").write_text("[bad](C:/secret.txt)\n[bad2](docs\\x.md)\n[Guide][g]\n\n[g]: docs/a file.md\n", encoding="utf-8")
    issues = audit_file_integrity(root).issues
    codes = [issue.category.split(":", 1)[0] for issue in issues]
    assert codes.count("LINK001") >= 2
    assert "LINKREF002" not in codes


def test_release_audit_checks_directory_root_version_token(tmp_path):
    root = _minimal(tmp_path / "ai_code_filter_refactored_v20")
    assert "ARCHIVE001" in _codes(audit_release(root, run_cli_matrix=False))


def test_release_audit_uses_project_pyproject_version_not_tool_version(tmp_path):
    root = _minimal(tmp_path / "ai_code_filter_refactored_v25")
    (root / "pyproject.toml").write_text(
        '[tool.demo]\nversion="9.9.9"\n[project]\nname="x"\nversion="0.25.0"\n[project.scripts]\nai-code-filter="ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    write_manifest(root)
    assert "REL003" not in _codes(audit_release(root, run_cli_matrix=False))


def test_release_audit_rejects_openai_mandatory_even_if_optional_groups_exist(tmp_path):
    root = _minimal(tmp_path / "ai_code_filter_refactored_v25")
    (root / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="0.25.0"\ndependencies=["openai"]\n[project.optional-dependencies]\ntest=[]\n[project.scripts]\nai-code-filter="ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    write_manifest(root)
    assert "REL006" in _codes(audit_release(root, run_cli_matrix=False))


def test_release_audit_requires_real_console_script_not_comment(tmp_path):
    root = _minimal(tmp_path / "ai_code_filter_refactored_v25")
    (root / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="0.25.0"\n# ai-code-filter = "ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    write_manifest(root)
    assert "REL005" in _codes(audit_release(root, run_cli_matrix=False))
