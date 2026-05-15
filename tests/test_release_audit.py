from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.models import Severity
from ai_code_filter.release.audit import audit_release
from ai_code_filter.integrity import write_manifest


def make_clean_project(root: Path, version: str = "0.17.0") -> Path:
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "tests").mkdir()
    (root / "ai_filter.py").write_text("from ai_code_filter.cli import main\nraise SystemExit(main())\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(f'[project]\nname="x"\nversion = "{version}"\n[project.scripts]\nai-code-filter = "ai_code_filter.cli:main"\n', encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "README.md").write_text(f"Release {version} v17\n", encoding="utf-8")
    write_manifest(root)
    return root


def test_release_audit_passes_clean_project_without_cli_matrix(tmp_path: Path):
    report = audit_release(make_clean_project(tmp_path / "ai_code_filter_refactored_v17"), run_cli_matrix=False)
    assert report.summary()["TOTAL"] == 0


def test_release_audit_detects_version_mismatch(tmp_path: Path):
    root = tmp_path / "pkg_v17"
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="x"\nversion = "0.17.0"\n', encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text('__version__ = "0.16.0"\n', encoding="utf-8")
    report = audit_release(root, run_cli_matrix=False)
    assert any(issue.category.startswith("REL003") for issue in report.issues)


def test_release_audit_detects_stale_docs(tmp_path: Path):
    root = tmp_path / "pkg_v17"
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="x"\nversion = "0.17.0"\n', encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text('__version__ = "0.17.0"\n', encoding="utf-8")
    (root / "README.md").write_text('Old docs v15', encoding="utf-8")
    report = audit_release(root, run_cli_matrix=False)
    assert any(issue.category.startswith("REL004") for issue in report.issues)


def test_release_audit_detects_archive_root_mismatch(tmp_path: Path):
    root = tmp_path / "wrong_root"
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="x"\nversion = "0.17.0"\n', encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text('__version__ = "0.17.0"\n', encoding="utf-8")
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for path in root.rglob("*"):
            if path.is_file():
                zf.write(path, Path("wrong_root") / path.relative_to(root))
    report = audit_release(archive, run_cli_matrix=False)
    assert any(issue.category.startswith("ARCHIVE001") for issue in report.issues)


def test_release_audit_detects_archive_hygiene(tmp_path: Path):
    root = tmp_path / "ai_code_filter_refactored_v17"
    (root / "ai_code_filter" / "__pycache__").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="x"\nversion = "0.17.0"\n', encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text('__version__ = "0.17.0"\n', encoding="utf-8")
    (root / "ai_code_filter" / "__pycache__" / "x.pyc").write_bytes(b"bad")
    report = audit_release(root, run_cli_matrix=False)
    assert any(issue.category.startswith("HYGIENE001") for issue in report.issues)


def test_release_audit_cli_command_writes_report(tmp_path: Path):
    out = tmp_path / "nested" / "release.json"
    target = make_clean_project(tmp_path / "ai_code_filter_refactored_v17")
    code = main(["release-audit", str(target), "--skip-cli-matrix", "--output", str(out)])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["TOTAL"] == 0


def test_release_audit_cli_ci_fails_on_detected_problem(tmp_path: Path):
    root = tmp_path / "bad_v17"
    (root / "ai_code_filter").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="x"\nversion = "0.17.0"\n', encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text('__version__ = "0.16.0"\n', encoding="utf-8")
    assert main(["release-audit", str(root), "--skip-cli-matrix", "--ci"]) == 1
