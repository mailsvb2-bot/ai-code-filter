from __future__ import annotations

from pathlib import Path

from ai_code_filter.assistant.capabilities import assistant_capability_matrix
from ai_code_filter.assistant.patch_plan import build_patch_plan
from ai_code_filter.assistant.report_explainer import explain_report
from ai_code_filter.assistant.review_plan import build_review_plan
from ai_code_filter.cli import main


def sample_report():
    return {
        "issues": [
            {
                "file": "app.py",
                "category": "PYDF001: SQL injection",
                "severity": "CRITICAL",
                "detector": "python_dataflow",
                "description": "Tainted value reaches SQL sink.",
                "recommendation": "Use parameterized queries.",
                "line_number": 12,
            },
            {
                "file": "view.py",
                "category": "TXT002: marker",
                "severity": "MEDIUM",
                "detector": "rule_catalog",
                "description": "Marker found.",
                "recommendation": "Resolve marker.",
            },
        ],
        "failed_files": [],
        "skipped_files": [{"file": "<pyright>", "reason": "not installed"}],
        "summary": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "TOTAL": 2, "FAILED_FILES": 0, "SKIPPED_FILES": 1},
    }


def test_assistant_capability_matrix_is_explicit():
    matrix = assistant_capability_matrix()
    from ai_code_filter import __version__
    assert matrix["version"] == __version__
    assert any(item["id"] == "AC003" for item in matrix["capabilities"])
    assert any("No network" in item for item in matrix["non_goals"])


def test_review_plan_builds_prioritized_queues():
    plan = build_review_plan(sample_report())
    assert plan["counts"]["P0"] == 1
    assert plan["counts"]["P2"] == 1
    assert plan["maturity_score"] < 100
    assert "benchmark" in " ".join(plan["verification_commands"])


def test_patch_plan_uses_recommendations():
    plan = build_patch_plan(sample_report())
    assert plan["items"][0]["priority"] == "P0"
    assert plan["items"][0]["action"] == "Use parameterized queries."


def test_report_explainer_markdown_contains_stop_condition():
    text = explain_report(sample_report(), as_markdown=True)
    assert "# AI Code Filter assistant review" in text
    assert "Stop condition" in text
    assert "P0" in text


def test_assistant_cli_commands(tmp_path: Path):
    report = tmp_path / "report.json"
    report.write_text(__import__("json").dumps(sample_report()), encoding="utf-8")
    caps = tmp_path / "caps.json"
    review = tmp_path / "review.md"
    plan = tmp_path / "plan.json"
    patch = tmp_path / "patch.json"
    prompts = tmp_path / "prompts.json"
    assert main(["assistant-capabilities", "--output", str(caps)]) == 0
    assert main(["explain-report", str(report), "--output", str(review)]) == 0
    assert main(["review-plan", str(report), "--output", str(plan)]) == 0
    assert main(["patch-plan", str(report), "--output", str(patch)]) == 0
    assert main(["prompt-pack", "--output", str(prompts)]) == 0
    assert caps.exists() and review.exists() and plan.exists() and patch.exists() and prompts.exists()
