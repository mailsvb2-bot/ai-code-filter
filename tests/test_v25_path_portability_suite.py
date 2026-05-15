from ai_code_filter.path_portability import path_portability_cases, path_portability_suite_summary, run_path_portability_suite


def test_path_portability_suite_is_focused_and_passing() -> None:
    report = run_path_portability_suite()
    assert not report.issues
    assert not report.failed_files
    assert len(path_portability_cases()) >= 19


def test_path_portability_summary_exposes_threat_classes() -> None:
    summary = path_portability_suite_summary()
    assert summary["case_count"] == len(path_portability_cases())
    assert "windows_reserved_names" in summary["threat_classes"]
    assert "unsafe_zip_member_names" in summary["threat_classes"]
    assert summary["families"].get("path_portability", 0) >= 10
