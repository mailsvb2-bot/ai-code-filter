from ai_code_filter.benchmarks import run_built_in_benchmark


def test_built_in_benchmark_expectations_pass():
    report = run_built_in_benchmark()
    assert report["passed"] is True
    assert report["metrics"]["false_positive_expectations"] == 0
    assert report["metrics"]["false_negative_expectations"] == 0
    assert report["metrics"]["recall_on_expectations"] == 1.0
