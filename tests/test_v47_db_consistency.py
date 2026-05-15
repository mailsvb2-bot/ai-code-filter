from __future__ import annotations

from ai_code_filter.cli import main
from ai_code_filter.config import RuntimeConfig
from ai_code_filter.db_consistency import audit_db_consistency
from ai_code_filter.pipeline import AnalysisPipeline


def test_db_consistency_detects_env_sqlite_postgres_mismatch(tmp_path):
    env = tmp_path / ".env.example"
    env.write_text("DATABASE_URL=sqlite:///local.db\nPOSTGRES_DSN=postgresql://user:pass@db/app\n", encoding="utf-8")
    report = audit_db_consistency(tmp_path)
    categories = {issue.category for issue in report.issues}
    assert "DB002: Runtime DB backend mismatch" in categories
    assert "DB004: Conflicting database env contract" in categories


def test_db_consistency_detects_project_array_backend_mismatch(tmp_path):
    cfg = tmp_path / "settings.py"
    cfg.write_text(
        "DATABASES = [\n"
        "    'sqlite:///local.db',\n"
        "    'postgresql://user:pass@db/app',\n"
        "]\n",
        encoding="utf-8",
    )
    report = audit_db_consistency(tmp_path)
    assert any(issue.category == "DB001: Mixed database backends in one file" for issue in report.issues)


def test_db_consistency_flags_prod_sqlite_fallback(tmp_path):
    cfg = tmp_path / "deploy" / "production.env"
    cfg.parent.mkdir()
    cfg.write_text("DATABASE_URL=sqlite:///prod.db\n", encoding="utf-8")
    report = audit_db_consistency(tmp_path)
    assert any(issue.category == "DB003: SQLite appears in production-like config" for issue in report.issues)


def test_db_consistency_pipeline_and_cli(tmp_path, capsys):
    cfg = tmp_path / "config.py"
    cfg.write_text("DATABASE_URL = 'sqlite:///local.db'\nPOSTGRES_URL = 'postgresql://db/app'\n", encoding="utf-8")
    report = AnalysisPipeline(RuntimeConfig(enable_ai_review=False, enable_drift=False)).analyze_paths([str(tmp_path)])
    assert any(issue.detector == "db_consistency" for issue in report.issues)
    code = main(["db-consistency", str(tmp_path), "--ci"])
    assert code == 1
    assert "DB002" in capsys.readouterr().out
