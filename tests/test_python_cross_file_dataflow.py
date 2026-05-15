from pathlib import Path

from ai_code_filter.analyzers.python_cross_file_dataflow import PythonCrossFileDataFlowAnalyzer
from ai_code_filter.models import FilePayload


def payload(tmp_path: Path, rel: str, code: str) -> FilePayload:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code, encoding="utf-8")
    return FilePayload(path=path, project_root=tmp_path, content=code)


def test_cross_file_tainted_source_reaches_imported_sql_wrapper(tmp_path):
    source = payload(tmp_path, "web.py", "from flask import request\n\ndef current_id():\n    return request.args.get('id')\n")
    db = payload(tmp_path, "db.py", "def run_query(q, cursor):\n    cursor.execute(q)\n")
    app = payload(tmp_path, "app.py", "from web import current_id\nfrom db import run_query\n\ndef handler(cursor):\n    value = current_id()\n    run_query('select * from users where id=' + value, cursor)\n")
    analyzer = PythonCrossFileDataFlowAnalyzer([source, db, app])
    issues = analyzer.analyze(app)
    assert any(issue.category.startswith("PYXDF001") for issue in issues)


def test_cross_file_sanitized_value_is_not_reported(tmp_path):
    source = payload(tmp_path, "web.py", "from flask import request\n\ndef current_id():\n    return request.args.get('id')\n")
    db = payload(tmp_path, "db.py", "def run_query(q, cursor):\n    cursor.execute(q)\n")
    app = payload(tmp_path, "app.py", "from html import escape\nfrom web import current_id\nfrom db import run_query\n\ndef handler(cursor):\n    value = escape(current_id())\n    run_query('select * from users where id=' + value, cursor)\n")
    analyzer = PythonCrossFileDataFlowAnalyzer([source, db, app])
    issues = analyzer.analyze(app)
    assert not any(issue.category.startswith("PYXDF001") for issue in issues)


def test_cross_file_tainted_value_reaches_imported_shell_wrapper(tmp_path):
    source = payload(tmp_path, "web.py", "import os\n\ndef target():\n    return os.getenv('TARGET')\n")
    ops = payload(tmp_path, "ops.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    app = payload(tmp_path, "app.py", "from web import target\nfrom ops import run\n\ndef handler():\n    run('ping ' + target())\n")
    analyzer = PythonCrossFileDataFlowAnalyzer([source, ops, app])
    issues = analyzer.analyze(app)
    assert any(issue.category.startswith("PYXDF002") for issue in issues)
