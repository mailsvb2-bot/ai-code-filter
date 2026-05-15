from pathlib import Path

from ai_code_filter.llm.prompts import CATEGORY_TITLES, ERROR_CATALOG
from ai_code_filter.analyzers.chain_inspector import build_chain_nodes, ChainInspectorAnalyzer
from ai_code_filter.models import FilePayload
from ai_code_filter.pipeline_integrity import validate_pipeline_integrity


def test_ai_prompt_has_52_categories_and_1000_plus_examples():
    assert len(CATEGORY_TITLES) == 52
    assert "TOTAL_EXAMPLES: 1040" in ERROR_CATALOG


def test_chain_inspector_builds_dependency_chains(tmp_path):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("import b\n\ndef main():\n    return b.helper()\n", encoding="utf-8")
    b.write_text("def helper():\n    return 1\n", encoding="utf-8")
    payloads = [FilePayload(a, tmp_path, a.read_text(encoding="utf-8")), FilePayload(b, tmp_path, b.read_text(encoding="utf-8"))]
    nodes = build_chain_nodes(payloads)
    inspector = ChainInspectorAnalyzer(nodes)
    chains = inspector.dependency_chains()
    assert any("a.py" in chain[0] for chain in chains if chain)


def test_pipeline_integrity_self_check_is_green():
    root = Path(__file__).resolve().parents[1]
    assert validate_pipeline_integrity(root) == []
