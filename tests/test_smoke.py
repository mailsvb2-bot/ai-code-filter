from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.filesystem import split_with_overlap
from ai_code_filter.analyzers.python_contract import compare_contracts


def test_split_with_overlap_roundtrip_shape():
    chunks = split_with_overlap("a" * 100, chunk_size=40, overlap=5)
    assert len(chunks) == 3
    assert all(chunks)


def test_contract_detects_removed_function():
    issues = compare_contracts("def a():\n    return 1\n", "", file="x.py")
    assert issues
    assert issues[0].severity.value == "CRITICAL"


def test_cli_no_ai_on_temp_project(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("def x():\n    return None\n", encoding="utf-8")
    assert main(["analyze", str(tmp_path), "--no-ai"]) == 0


def test_duplicate_detector_does_not_flag_class_init_methods(tmp_path: Path):
    source = tmp_path / "classes.py"
    source.write_text("class A:\n    def __init__(self, x):\n        self.x = x\nclass B:\n    def __init__(self, y, z):\n        self.y = y\n", encoding="utf-8")
    assert main(["analyze", str(source), "--no-ai"]) == 0
