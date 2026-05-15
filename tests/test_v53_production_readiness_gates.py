from __future__ import annotations

import json
from pathlib import Path

from ai_code_filter.behavior_audit import audit_behavior
from ai_code_filter.deployment_audit import audit_deployment
from ai_code_filter.external_audit import audit_external_tools
from ai_code_filter.migration_audit import audit_migrations
from ai_code_filter.supply_chain_audit import audit_supply_chain
from ai_code_filter.type_audit import audit_type_intelligence


def _cats(report):
    return {issue.category for issue in report.issues}


def test_type_audit_detects_untyped_public_api_and_type_ignore(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from typing import Any\n"
        "def public(x):\n"
        "    return x  # type: ignore\n"
        "def typed(x: int) -> int:\n"
        "    return x\n",
        encoding="utf-8",
    )
    report, summary = audit_type_intelligence(tmp_path, engines=(), max_untyped_public=0)
    cats = _cats(report)
    assert "TYPE030: untyped public API budget exceeded" in cats
    assert "TYPE031: type ignore lacks rationale" in cats
    assert summary.untyped_public_functions >= 1


def test_external_audit_unavailable_tool_is_honest_skip_not_crash(tmp_path: Path):
    report, summary = audit_external_tools(tmp_path, tools=("definitely-not-a-tool",), require_tools=False)
    assert not report.issues
    assert report.skipped_files
    assert summary.tools[0].available is False


def test_deployment_audit_detects_docker_secret_and_missing_healthcheck(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCOPY .env /app/.env\nCMD python app.py\n", encoding="utf-8")
    report = audit_deployment(tmp_path)
    cats = _cats(report)
    assert "DEPLOY010: Dockerfile lacks HEALTHCHECK" in cats
    assert "DEPLOY011: Dockerfile copies env secrets" in cats


def test_migration_audit_detects_db_config_without_migrations(tmp_path: Path):
    (tmp_path / "settings.py").write_text('DATABASE_URL = "postgresql://db/app"\n', encoding="utf-8")
    report = audit_migrations(tmp_path)
    assert "MIG001: DB config without migrations" in _cats(report)


def test_supply_chain_audit_detects_unpinned_and_direct_url(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests>=2\ngit+https://example.com/repo.git\n", encoding="utf-8")
    report = audit_supply_chain(tmp_path)
    cats = _cats(report)
    assert "SUPPLY010: unpinned dependency" in cats
    assert "SUPPLY020: direct URL dependency" in cats


def test_behavior_audit_strips_secret_env_and_blocks_network(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SHOULD_BE_SECRET_TOKEN", "leaked")
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def secret_visible():\n"
        "    return os.environ.get('SHOULD_BE_SECRET_TOKEN')\n"
        "def open_socket():\n"
        "    import socket\n"
        "    socket.socket()\n"
        "    return True\n",
        encoding="utf-8",
    )
    spec = tmp_path / "behavior.json"
    spec.write_text(json.dumps({"probes": [
        {"type": "function", "name": "secret stripped", "target": "app:secret_visible", "expect": {"equals": None}},
        {"type": "function", "name": "network denied", "target": "app:open_socket", "expect": {"raises": "RuntimeError"}},
    ]}), encoding="utf-8")
    report, summary = audit_behavior(tmp_path, spec=spec, deny_network=True, deny_secret_env=True)
    assert not report.issues
    assert summary.to_dict()["passed"] == 2
