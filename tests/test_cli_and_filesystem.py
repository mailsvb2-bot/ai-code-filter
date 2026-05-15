from pathlib import Path

from ai_code_filter.cli import main
from ai_code_filter.filesystem import collect_files


def test_list_rules_command_runs(capsys):
    assert main(["list-rules", "--language", "python"]) == 0
    out = capsys.readouterr().out
    assert "PY001" in out
    assert "PY023" in out


def test_collect_files_ignores_cache_and_state_dirs(tmp_path: Path):
    good = tmp_path / "app.py"
    good.write_text("print('ok')", encoding="utf-8")
    ignored = tmp_path / ".ai-code-filter" / "state.py"
    ignored.parent.mkdir()
    ignored.write_text("print('bad')", encoding="utf-8")
    pycache = tmp_path / "__pycache__" / "x.py"
    pycache.parent.mkdir()
    pycache.write_text("print('bad')", encoding="utf-8")
    assert collect_files([str(tmp_path)], [".py"]) == [good]

def test_analyze_no_drift_does_not_create_state_dir(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    assert main(["analyze", str(source), "--no-ai", "--no-drift"]) == 0
    assert not (tmp_path / ".ai-code-filter").exists()
