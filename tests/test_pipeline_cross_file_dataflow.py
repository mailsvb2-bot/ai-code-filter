from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline


def test_pipeline_reports_cross_file_python_dataflow(tmp_path):
    (tmp_path / "web.py").write_text("from flask import request\n\ndef current_id():\n    return request.args.get('id')\n", encoding="utf-8")
    (tmp_path / "db.py").write_text("def run_query(q, cursor):\n    cursor.execute(q)\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("from web import current_id\nfrom db import run_query\n\ndef handler(cursor):\n    value = current_id()\n    run_query('select * from users where id=' + value, cursor)\n", encoding="utf-8")
    report = AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False)).analyze_paths([str(tmp_path)])
    assert any(issue.category.startswith("PYXDF001") for issue in report.issues)
