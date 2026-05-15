from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .blindspots import BlindSpotCase, _categories, _has_expected, _issue, blindspot_cases
from .models import Issue, Report, Severity

PATH_PORTABILITY_FAMILIES = {
    "path_portability",
    "path_collisions",
    "manifest_path_parsing",
    "markdown_links",
    "zip_integrity",
}

EXPLICIT_PATH_PORTABILITY_CASE_IDS = {
    "manifest_windows_drive",
    "manifest_double_space_path",
    "manifest_leading_space_path",
    "manifest_trailing_space_path",
    "manifest_backslash_path",
    "manifest_traversal_path",
    "manifest_reserved_windows_name",
    "manifest_colon_ads_path",
    "manifest_trailing_dot_path",
    "manifest_percent_encoded_traversal",
    "tree_directory_case_collision",
    "tree_reserved_windows_name",
    "tree_colon_ads_name",
    "tree_unicode_format_name",
    "markdown_windows_drive_link",
    "markdown_backslash_link",
    "markdown_percent_traversal",
    "zip_duplicate_member",
    "zip_windows_drive_member",
    "zip_backslash_member",
    "zip_control_char_member",
    "zip_reserved_windows_member",
    "zip_colon_ads_member",
    "zip_double_slash_member",
    "zip_case_insensitive_duplicate_member",
}


def path_portability_cases() -> list[BlindSpotCase]:
    """Return fixtures dedicated to path portability and archive-name bypasses.

    This suite is intentionally narrower than the full blind-spot suite: it focuses on
    cross-platform path ambiguity, Windows device names, alternate-data-stream style
    names, percent-encoded traversal/backslashes, case-insensitive collisions, control
    and Unicode format characters, and unsafe Markdown/archive path targets.
    """
    selected: list[BlindSpotCase] = []
    seen: set[str] = set()
    for case in blindspot_cases():
        if case.case_id in EXPLICIT_PATH_PORTABILITY_CASE_IDS or case.family in PATH_PORTABILITY_FAMILIES:
            if case.case_id not in seen:
                selected.append(case)
                seen.add(case.case_id)
    return selected


def run_path_portability_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-path-portability-") as tmp_s:
        base = Path(tmp_s)
        for case in path_portability_cases():
            case_dir = base / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            try:
                observed = case.runner(case_dir)
            except Exception as exc:
                report.add(Issue(
                    file=f"<path-portability:{case.case_id}>",
                    category="PATHPORT001: Path portability fixture crash",
                    severity=Severity.HIGH,
                    detector="path_portability_suite",
                    description=f"Path-portability fixture crashed: {exc}",
                    recommendation="Fix the fixture or the underlying path/archive detector.",
                ))
                continue
            if observed.skipped_files:
                report.record_skip(
                    f"<path-portability:{case.case_id}>",
                    "; ".join(item.get("reason", "skipped") for item in observed.skipped_files),
                )
                continue
            if not _has_expected(observed, case.expected_prefixes):
                base_issue = _issue(case, _categories(observed))
                report.add(Issue(
                    file=f"<path-portability:{case.case_id}>",
                    category="PATHPORT002: Path portability regression failure",
                    severity=Severity.HIGH,
                    detector="path_portability_suite",
                    description=base_issue.description,
                    recommendation="Add or repair the path portability/archive-name bypass detector and keep this fixture enabled.",
                ))
    return report


def path_portability_suite_summary() -> dict[str, object]:
    cases = path_portability_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "case_count": len(cases),
        "families": dict(sorted(families.items())),
        "threat_classes": [
            "windows_reserved_names",
            "windows_drive_and_ads_colon_paths",
            "percent_encoded_traversal_or_backslash",
            "unicode_control_and_format_characters",
            "case_insensitive_collisions",
            "unsafe_markdown_targets",
            "unsafe_zip_member_names",
            "ambiguous_manifest_path_serialization",
        ],
        "cases": [
            {"case_id": c.case_id, "family": c.family, "title": c.title, "expected_prefixes": list(c.expected_prefixes)}
            for c in cases
        ],
    }


def write_path_portability_summary(path: str | Path | None) -> None:
    """Write the path-portability fixture inventory.

    Returns None when no output path is provided.
    """
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(path_portability_suite_summary(), ensure_ascii=False, indent=2), encoding="utf-8")
