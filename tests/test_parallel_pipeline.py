from pathlib import Path

from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline


def test_parallel_pipeline_matches_serial_for_local_scan(tmp_path: Path):
    src = 'def f():\n    eval("1+1")\n'
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    (tmp_path / "b.py").write_text(src, encoding="utf-8")
    serial = AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False, workers=1)).analyze_paths([str(tmp_path)]).summary()
    parallel = AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False, workers=2)).analyze_paths([str(tmp_path)]).summary()
    assert parallel == serial
