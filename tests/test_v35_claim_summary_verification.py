from ai_code_filter.claim_summary_verification import (
    claim_summary_verification_suite_summary,
    run_claim_summary_verification_suite,
)


def test_claim_summary_verification_suite_passes():
    report = run_claim_summary_verification_suite()
    assert not report.issues
    assert not report.failed_files
    assert not report.skipped_files


def test_claim_summary_verification_summary_has_cases():
    summary = claim_summary_verification_suite_summary()
    assert summary["suite"] == "claim_summary_verification"
    assert summary["case_count"] >= 10
    assert "claim_summary" in summary["by_family"]
    assert "verification" in summary["by_family"]
