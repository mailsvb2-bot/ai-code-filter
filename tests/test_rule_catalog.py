from pathlib import Path

from ai_code_filter.analyzers.rule_catalog import RuleCatalogAnalyzer
from ai_code_filter.models import FilePayload
from ai_code_filter.rules import build_default_catalog


def payload(tmp_path: Path, source: str, name: str = "sample.py") -> FilePayload:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return FilePayload(path=path, project_root=tmp_path, content=source)


def rule_ids(issues):
    return {issue.category.split(":", 1)[0] for issue in issues}


def test_catalog_has_unique_explicit_rule_ids():
    catalog = build_default_catalog()
    ids = [rule.rule_id for rule in catalog.rules]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 39
    assert {"PY001", "PY010", "PY023", "PY028", "TXT003", "JS008"}.issubset(ids)
    assert catalog.coverage()["python"] >= 20


def test_security_and_error_rules_detect_concrete_locations(tmp_path: Path):
    source = '''
import pickle
import subprocess
import yaml
import os
import tempfile

API_TOKEN = "abcdefghijklmnopqrstuvwxyz123456"

def run(user_code, blob, raw):
    eval(user_code)
    pickle.loads(blob)
    yaml.load(raw)
    subprocess.run("echo hi", shell=True)
    os.system("echo hi")
    tempfile.mktemp()
    try:
        risky()
    except:
        pass
'''
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source))
    ids = rule_ids(issues)
    assert {"PY001", "PY002", "PY003", "PY004", "PY005", "PY006", "PY007", "PY012", "PY013"}.issubset(ids)
    assert all(issue.location or issue.line_number for issue in issues)


def test_network_async_money_and_correctness_rules(tmp_path: Path):
    source = '''
import requests
import time
import asyncio
import hashlib
from datetime import datetime
from math import *

price_rub: float = 10.5
api_token = random.random()

def f(items=[]):
    assert items is not None
    return open("x.txt", "w")

async def handler():
    time.sleep(1)
    asyncio.create_task(worker())
    return requests.get("https://example.com")

now = datetime.utcnow()
hashlib.md5(b"x")
'''
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source))
    ids = rule_ids(issues)
    assert {"PY008", "PY009", "PY010", "PY011", "PY014", "PY016", "PY017", "PY018", "PY019", "PY020", "PY023"}.issubset(ids)


def test_sql_logging_and_json_boundaries(tmp_path: Path):
    source = '''
import logging

def handle(conn, user_id, response, token):
    conn.execute(f"select * from users where id={user_id}")
    logging.info("token=%s", token)
    return response.json()
'''
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source))
    assert {"PY015", "PY021", "PY022"}.issubset(rule_ids(issues))


def test_safe_patterns_are_not_flagged(tmp_path: Path):
    source = '''
from decimal import Decimal
from datetime import datetime, timezone
import asyncio
import requests
import yaml

price_rub: Decimal = Decimal("10.50")

async def handler():
    await asyncio.sleep(1)
    return requests.get("https://example.com", timeout=10)

def parse(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)

now = datetime.now(timezone.utc)
'''
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source))
    assert not {"PY007", "PY008", "PY009", "PY010", "PY018"}.intersection(rule_ids(issues))


def test_text_claim_and_suppression_rules(tmp_path: Path):
    source = '"""Complete & Final Production Version"""\n# TODO: finish\nx = 1  # type: ignore\n'
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source))
    assert {"TXT001", "TXT002", "TXT003"}.issubset(rule_ids(issues))


def test_javascript_rules(tmp_path: Path):
    source = '''
console.log("debug")
eval(userCode)
document.body.innerHTML = html
localStorage.setItem("token", token)
const card = <div dangerouslySetInnerHTML={{__html: html}} />
'''
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source, "sample.tsx"))
    assert {"JS001", "JS002", "JS003", "JS004", "JS005"}.issubset(rule_ids(issues))

def test_expanded_network_config_and_js_rules(tmp_path: Path):
    py_source = '''
import requests
import urllib.request
import ssl

DEBUG = True

def app_run(app):
    requests.get("https://example.com", verify=False, timeout=5)
    urllib.request.urlopen("https://example.com")
    ssl._create_unverified_context()
    app.run(debug=True)
'''
    py_issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, py_source, "settings.py"))
    assert {"PY024", "PY025", "PY026", "PY027", "PY028"}.issubset(rule_ids(py_issues))

    js_source = '''
document.cookie = "session=" + token
<a href="https://example.com" target="_blank">x</a>
fetch("/api/users")
'''
    js_issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, js_source, "app.jsx"))
    assert {"JS006", "JS007", "JS008"}.issubset(rule_ids(js_issues))


def test_import_aliases_do_not_hide_security_rules(tmp_path: Path):
    source = '''
import requests as r
import pickle as p
from subprocess import run
from yaml import load, SafeLoader
from hashlib import md5, sha1

def f(blob, raw, cmd):
    r.get("https://example.com")
    r.post("https://example.com", verify=False, timeout=5)
    p.loads(blob)
    run(cmd, shell=True)
    load(raw)
    load(raw, Loader=SafeLoader)
    md5(b"x")
    sha1(b"x")
'''
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source, "alias_probe.py"))
    ids = rule_ids(issues)
    assert {"PY005", "PY006", "PY007", "PY008", "PY017", "PY024"}.issubset(ids)
    # SafeLoader alias must not suppress detection of the unsafe load(raw), and must not
    # create duplicate YAML findings for the safe load(raw, Loader=SafeLoader).
    yaml_findings = [issue for issue in issues if issue.category.startswith("PY007:")]
    assert len(yaml_findings) == 1


def test_rule_findings_include_canonical_evidence_for_aliases(tmp_path: Path):
    source = '''
import requests as r

def f():
    return r.get("https://example.com")
'''
    issues = RuleCatalogAnalyzer().analyze(payload(tmp_path, source, "evidence_alias.py"))
    request_issue = next(issue for issue in issues if issue.category.startswith("PY008:"))
    assert request_issue.confidence == "high"
    assert request_issue.evidence
    assert request_issue.evidence["raw_call"] == "r.get"
    assert request_issue.evidence["canonical_call"] == "requests.get"
