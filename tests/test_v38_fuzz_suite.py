from ai_code_filter.fuzzing import fuzz_suite_summary, run_fuzz_suite


def test_fuzz_suite_is_clean_and_has_generated_cases():
    report = run_fuzz_suite()
    assert report.summary()["TOTAL"] == 0
    summary = fuzz_suite_summary()
    assert summary["case_count"] >= 20
    assert summary["by_domain"]["encoded_separator"] >= 4
