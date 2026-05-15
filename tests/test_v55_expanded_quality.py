from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ai_code_filter.config import RuntimeConfig
from ai_code_filter.pipeline import AnalysisPipeline
from ai_code_filter.rule_quality import audit_rule_quality


def _categories(report):
    return {issue.category for issue in report.issues}


def test_expanded_framework_profiles_detect_framework_specific_risks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request, redirect, render_template_string\n"
        "from fastapi.responses import HTMLResponse\n"
        "from django.utils.safestring import mark_safe\n"
        "from sqlalchemy import text, create_engine\n"
        "def f():\n"
        "    render_template_string(request.args.get('tpl'))\n"
        "    redirect(request.args.get('next'))\n"
        "    return HTMLResponse(f'<b>{request.query_params.get(\"x\")}</b>')\n"
        "def d(x):\n"
        "    return mark_safe(x)\n"
        "def s(user):\n"
        "    return text(f'SELECT * FROM users WHERE name={user}')\n"
        "engine = create_engine('sqlite:///prod.db')  # production\n",
        encoding="utf-8",
    )
    cfg = RuntimeConfig(enable_ai_review=False, enable_drift=False, profiles=("flask", "fastapi", "django", "sqlalchemy"))
    report = AnalysisPipeline(cfg).analyze_paths([str(tmp_path)])
    cats = _categories(report)
    assert "flask.render_template_string.risk" in cats
    assert "flask.open_redirect.risk" in cats
    assert "fastapi.html_response.dynamic_html" in cats
    assert "django.mark_safe.risk" in cats
    assert "sqlalchemy.text.fstring_sql" in cats
    assert "sqlalchemy.prod_sqlite_engine" in cats


def test_messaging_and_autonomy_canon_profiles_got_stricter(tmp_path: Path) -> None:
    (tmp_path / "bot.py").write_text(
        "async def h(callback_query):\n"
        "    await callback_query.message.answer('ok')\n"
        "async def main(dp):\n"
        "    await dp.start_polling()\n"
        "    # webhook setup nearby\n",
        encoding="utf-8",
    )
    (tmp_path / "capability.py").write_text("FEATURE = 'new autonomy capability'\n", encoding="utf-8")
    cfg = RuntimeConfig(enable_ai_review=False, enable_drift=False, profiles=("messaging-bot", "autonomy-canon"))
    report = AnalysisPipeline(cfg).analyze_paths([str(tmp_path)])
    cats = _categories(report)
    assert "messaging.callback_query.missing_answer_signal" in cats
    assert "messaging.transport.polling_webhook_conflict" in cats
    assert "autonomy_canon.admin_surface.missing_signal" in cats


def test_rule_quality_audits_rule_passport_fields(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_rule_x.py").write_text("def test_rule_x():\n    assert True\n", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    reg = docs / "RULE_OWNERSHIP.json"
    reg.write_text(json.dumps({
        "X001": {
            "owner": "security",
            "status": "stable",
            "precision": "high",
            "coverage": ["direct_call"],
            "known_gaps": ["dynamic_dispatch"],
            "tests": ["test_rule_x"],
        }
    }), encoding="utf-8")
    report, summary = audit_rule_quality(tmp_path, reg)
    assert not report.issues
    assert summary.rules == 1
    assert summary.rules_with_tests == 1


def test_rule_quality_cli_is_available(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_rule_x.py").write_text("def test_rule_x():\n    assert True\n", encoding="utf-8")
    reg = tmp_path / "rules.json"
    reg.write_text(json.dumps({
        "X001": {
            "owner": "security",
            "status": "stable",
            "precision": "medium",
            "coverage": ["direct_call"],
            "known_gaps": ["runtime_reflection"],
            "tests": ["test_rule_x"],
        }
    }), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "ai_filter.py", "rule-quality", str(tmp_path), "--registry", str(reg), "--ci"],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "No problems found" in proc.stdout
