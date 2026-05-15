from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline
from ai_code_filter.type_resolution.dependencies import DependencyResolver
from ai_code_filter.type_resolution.sdk_index import build_sdk_index
from ai_code_filter.type_resolution.type_tools import TypeToolAdapter


def test_dependency_resolver_reads_pyproject_and_package_json(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["python-dotenv>=1", "PyYAML"]\n', encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "latest"}, "devDependencies": {"typescript": "latest"}}), encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("", encoding="utf-8")

    manifest = DependencyResolver(tmp_path).resolve()

    assert "python-dotenv>=1" in manifest.python_dependencies
    assert "dotenv" in manifest.python_import_roots
    assert "yaml" in manifest.python_import_roots
    assert "react" in manifest.javascript_dependencies
    assert "poetry.lock" in manifest.lockfiles


def test_sdk_index_metadata_mode_does_not_import_packages(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["json"]\n', encoding="utf-8")
    manifest = DependencyResolver(tmp_path).resolve()

    index = build_sdk_index(manifest, extra_import_roots=["json"], import_packages=False)

    assert index.package("json") is not None
    assert index.package("json").available is True
    assert index.package("json").imported is False


def test_sdk_index_import_mode_collects_public_attributes(tmp_path: Path):
    manifest = DependencyResolver(tmp_path).resolve()

    index = build_sdk_index(manifest, extra_import_roots=["json"], import_packages=True)

    pkg = index.package("json")
    assert pkg is not None
    assert pkg.imported is True
    assert pkg.has_attribute("loads")


def test_unknown_call_validator_uses_sdk_index_when_enabled(tmp_path: Path):
    (tmp_path / "sample.py").write_text('import json\njson.no_such_public_method("x")\n', encoding="utf-8")
    config = RuntimeConfig(enable_ai_review=False, enable_drift=False, extensions=(".py",), enable_sdk_index=True, enable_sdk_imports=True, enable_unknown_call_check=True)

    report = AnalysisPipeline(config).analyze_paths([str(tmp_path)])

    assert any(issue.detector == "unknown_call_validator" and "no_such_public_method" in issue.description for issue in report.issues)


def test_type_tool_adapter_absent_tools_are_non_blocking(tmp_path: Path):
    result = TypeToolAdapter(tmp_path).run_pyright()

    if not result.available:
        assert result.issues == ()


def test_unknown_call_validator_handles_dotted_module_alias_without_false_positive(tmp_path: Path):
    (tmp_path / "sample.py").write_text(
        'import xml.etree.ElementTree as ET\nroot = ET.Element("root")\nET.SubElement(root, "child")\nET.fromstring("<root />")\n',
        encoding="utf-8",
    )
    config = RuntimeConfig(
        enable_ai_review=False,
        enable_drift=False,
        extensions=(".py",),
        enable_sdk_index=True,
        enable_unknown_call_check=True,
    )

    report = AnalysisPipeline(config).analyze_paths([str(tmp_path)])

    assert not [issue for issue in report.issues if issue.detector == "unknown_call_validator"]


def test_unknown_call_validator_does_not_overwrite_top_level_dotted_import(tmp_path: Path):
    (tmp_path / "sample.py").write_text(
        'import importlib\nimport importlib.util\nmodule = importlib.import_module("json")\n',
        encoding="utf-8",
    )
    config = RuntimeConfig(
        enable_ai_review=False,
        enable_drift=False,
        extensions=(".py",),
        enable_sdk_index=True,
        enable_unknown_call_check=True,
    )

    report = AnalysisPipeline(config).analyze_paths([str(tmp_path)])

    assert not [issue for issue in report.issues if issue.detector == "unknown_call_validator"]


def test_type_tools_pipeline_reports_missing_tools_as_skipped(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("ai_code_filter.type_resolution.type_tools.shutil.which", lambda _: None)
    (tmp_path / "sample.py").write_text("x = 1\n", encoding="utf-8")
    config = RuntimeConfig(enable_ai_review=False, enable_drift=False, extensions=(".py",), enable_type_tools=True)

    report = AnalysisPipeline(config).analyze_paths([str(tmp_path)])

    skipped = {entry["file"] for entry in report.skipped_files}
    assert "<pyright>" in skipped
    assert "<mypy>" in skipped


def test_type_check_cli_reports_missing_tools_as_skipped(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr("ai_code_filter.type_resolution.type_tools.shutil.which", lambda _: None)
    from ai_code_filter.cli import main

    code = main(["type-check", str(tmp_path)])
    out = capsys.readouterr().out

    assert code == 0
    assert "Skipped files: 2" in out
