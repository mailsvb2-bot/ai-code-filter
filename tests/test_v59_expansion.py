from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.github_integration import annotation_commands, pr_comment_markdown
from ai_code_filter.models import Issue, Report, Severity
from ai_code_filter.normalization_packs import list_packs, normalize_with_pack
from ai_code_filter.real_world_corpus import write_default_corpus, audit_corpus_manifest
from ai_code_filter.precision_recall import benchmark_precision_recall
from ai_code_filter.sarif_github import audit_github_sarif
from ai_code_filter.dashboard import write_trend_dashboard
from ai_code_filter.framework_profile_audit import audit_framework_profiles
from ai_code_filter.plugin_api import validate_plugin_manifest
from ai_code_filter.docker_sandbox import build_behavior_sandbox_command
from ai_code_filter.incremental_pr import audit_incremental_pr
from ai_code_filter.artifacts import write_sarif_report
from ai_code_filter.reporting import write_json_report


def test_github_annotations_and_pr_comment():
    r = Report(); r.add(Issue(file='app.py', line_number=3, category='X001: risk', severity=Severity.HIGH, detector='t', description='bad', recommendation='fix'))
    cmds, summary = annotation_commands(r)
    assert cmds and '::error file=app.py,line=3' in cmds[0]
    assert summary.errors == 1
    assert 'AI Code Filter review' in pr_comment_markdown(r)


def test_normalization_packs_semgrep(tmp_path: Path):
    data = {"results":[{"check_id":"python.lang.security.audit","path":"app.py","start":{"line":7},"extra":{"severity":"ERROR","message":"bad"}}]}
    f = tmp_path / 'semgrep.json'; f.write_text(json.dumps(data), encoding='utf-8')
    report = normalize_with_pack('semgrep', f)
    assert report.issues and report.issues[0].category.startswith('external.semgrep')
    assert {p['tool'] for p in list_packs()['first_class_normalization_packs']} >= {'semgrep','bandit','ruff','pyright'}


def test_real_world_corpus_manifest(tmp_path: Path):
    m = tmp_path / 'corpus.json'; write_default_corpus(m)
    report, summary = audit_corpus_manifest(m, min_projects=20)
    assert not report.has_blocking_issues()
    assert summary.projects >= 20


def test_precision_recall_report(tmp_path: Path):
    expected = tmp_path / 'expected.json'; observed = tmp_path / 'observed.json'
    expected.write_text(json.dumps({'cases':[{'path':'bad.py','must_find':['SQLI']}]}), encoding='utf-8')
    observed.write_text(json.dumps({'issues':[{'category':'SQLI','file':'bad.py'}], 'summary': {'TOTAL': 1}}), encoding='utf-8')
    report, summary = benchmark_precision_recall(expected, observed, min_recall=1.0, min_precision_proxy=1.0)
    assert not report.has_blocking_issues()
    assert summary.recall == 1.0


def test_sarif_github_and_dashboard(tmp_path: Path):
    r = Report(); r.add(Issue(file='app.py', line_number=1, category='A001: a', severity=Severity.MEDIUM, detector='x', description='d', recommendation='r'))
    sarif = tmp_path / 'out.sarif'; write_sarif_report(r, sarif)
    assert not audit_github_sarif(sarif).has_blocking_issues()
    native = tmp_path / 'report.json'; write_json_report(r, native)
    html = tmp_path / 'dash.html'; write_trend_dashboard([native], html)
    assert 'AI Code Filter Trends' in html.read_text(encoding='utf-8')


def test_framework_plugin_docker_incremental(tmp_path: Path):
    app = tmp_path / 'app.py'
    app.write_text('from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef x(request):\n    return None\n', encoding='utf-8')
    freport, fsum = audit_framework_profiles(tmp_path, profiles=('django',))
    assert freport.issues and fsum.signals
    pack = tmp_path / 'pack.py'
    pack.write_text('class P:\n    name="demo"\n    version="1"\n    def analyze_text(self,path,text): return []\ndef register_policy_pack(): return P()\n', encoding='utf-8')
    (tmp_path / 'policy_packs.json').write_text(json.dumps({'packs':[{'path':'pack.py'}]}), encoding='utf-8')
    issues, psum = validate_plugin_manifest(tmp_path)
    assert not issues and psum.packs == 1
    _dreport, dsum = build_behavior_sandbox_command(tmp_path)
    assert 'docker' in dsum.command[0]
    _preport, ps = audit_incremental_pr(tmp_path, changed_files=('app.py',), radius=1)
    assert ps.changed_files == 1
