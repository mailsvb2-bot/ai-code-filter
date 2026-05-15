from pathlib import Path

from ai_code_filter.analyzers.python_dataflow import PythonDataFlowAnalyzer
from ai_code_filter.models import FilePayload


def payload(tmp_path: Path, source: str, name: str = "app.py") -> FilePayload:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return FilePayload(path=path, project_root=tmp_path, content=source)


def ids(issues):
    return {issue.category.split(":", 1)[0] for issue in issues}


def test_detects_tainted_request_value_in_sql(tmp_path: Path):
    source = '''
def handler(request, conn):
    user_id = request.args.get("id")
    return conn.execute(f"select * from users where id={user_id}")
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert "PYDF001" in ids(issues)
    assert all(issue.line_number for issue in issues)


def test_parameterized_sql_is_not_reported_as_tainted_sql(tmp_path: Path):
    source = '''
def handler(request, conn):
    user_id = request.args.get("id")
    return conn.execute("select * from users where id=%s", (user_id,))
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert "PYDF001" not in ids(issues)


def test_detects_tainted_shell_and_template_sinks(tmp_path: Path):
    source = '''
import os
from flask import render_template_string

def handler(request):
    cmd = request.form.get("cmd")
    page = request.get_json()
    os.system("run " + cmd)
    return render_template_string(page)
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert {"PYDF002", "PYDF003"}.issubset(ids(issues))


def test_detects_interfunction_tainted_sql(tmp_path: Path):
    source = '''
def get_user_id(request):
    return request.args.get("id")

def handler(request, conn):
    user_id = get_user_id(request)
    conn.execute(f"select * from users where id={user_id}")
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert "PYDF001" in ids(issues)


def test_sanitizer_stops_template_taint(tmp_path: Path):
    source = '''
from markupsafe import escape
from flask import render_template_string

def handler(request):
    page = request.args.get("page")
    safe = escape(page)
    return render_template_string(safe)
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert "PYDF003" not in ids(issues)


def test_dataflow_resolves_import_aliases_for_shell_sinks(tmp_path):
    source = '''
from subprocess import run
from flask import request

def handler():
    cmd = request.args.get("cmd")
    return run(cmd, shell=True)
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert "PYDF002" in ids(issues)


def test_interprocedural_lite_tracks_helper_assignment_return(tmp_path: Path):
    source = '''
def get_query(request):
    q = request.args.get("q")
    return q

def handler(request, conn):
    query = get_query(request)
    conn.execute(f"select * from users where name='{query}'")
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert "PYDF001" in ids(issues)
    assert next(issue for issue in issues if issue.category.startswith("PYDF001:")).evidence["canonical_call"].endswith("execute")


def test_wrapper_detection_reports_tainted_shell_wrapper(tmp_path: Path):
    source = '''
from subprocess import run

def shell(cmd):
    return run(cmd, shell=True)

def handler(request):
    cmd = request.args.get("cmd")
    return shell(cmd)
'''
    issues = PythonDataFlowAnalyzer().analyze(payload(tmp_path, source))
    assert "PYDF002" in ids(issues)
