from __future__ import annotations

import json
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Iterable

from .integrity import MANIFEST_NAME, audit_file_integrity, generate_manifest, parse_manifest
from .models import Issue, Report, Severity
from .release.audit import audit_release


@dataclass(frozen=True)
class EncodedCollisionCase:
    """Regression fixture for encoded-separator, collision and structured duplicate hardening."""

    case_id: str
    title: str
    family: str
    expected_prefixes: tuple[str, ...]
    runner: Callable[[Path], Report]


def _categories(report: Report) -> set[str]:
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def _has_expected(report: Report, prefixes: tuple[str, ...]) -> bool:
    categories = _categories(report)
    return any(any(category.startswith(prefix) for category in categories) for prefix in prefixes)


def _suite_issue(case: EncodedCollisionCase, observed: Iterable[str]) -> Issue:
    observed_s = ", ".join(sorted(observed)) or "<none>"
    expected_s = ", ".join(case.expected_prefixes)
    return Issue(
        file=f"<encoded-collision:{case.case_id}>",
        category="ENCCOLL001: Encoded/collision hardening regression failure",
        severity=Severity.HIGH,
        detector="encoded_collision_hardening_suite",
        description=(
            f"Encoded separator/collision/structured duplicate fixture was not detected: {case.title}. "
            f"Expected one of [{expected_s}], observed [{observed_s}]."
        ),
        recommendation="Add or repair encoded-separator, normalized-collision or structured duplicate validation and keep this fixture enabled.",
    )


def _ok_issue(case_id: str, title: str) -> Issue:
    return Issue(
        file=f"<encoded-collision:{case_id}>",
        category="ENCCOLL_OK: False-positive guard accepted",
        severity=Severity.LOW,
        detector="encoded_collision_hardening_suite",
        description=title,
        recommendation="No action.",
    )


def _manifest_report(text: str, tmp: Path) -> Report:
    manifest = tmp / MANIFEST_NAME
    manifest.write_text(text, encoding="utf-8")
    report = Report()
    try:
        parse_manifest(manifest)
    except Exception as exc:
        report.add(Issue(
            file=str(manifest),
            category="MANIFEST001: Artifact integrity",
            severity=Severity.CRITICAL,
            detector="encoded_collision_hardening_suite",
            description=str(exc),
            recommendation="Reject encoded separators, ambiguous paths and normalized manifest collisions.",
        ))
    return report


def _manifest_line(rel: str, digest: str | None = None, size: int = 1) -> str:
    return f"{digest or ('a' * 64)}  {rel}  size={size}\n"


def _manifest_rel(tmp: Path, rel: str) -> Report:
    return _manifest_report(_manifest_line(rel), tmp)


def _manifest_percent_slash(tmp: Path) -> Report:
    return _manifest_rel(tmp, "docs%2Fguide.md")


def _manifest_percent_slash_lower(tmp: Path) -> Report:
    return _manifest_rel(tmp, "docs%2fguide.md")


def _manifest_double_encoded_slash(tmp: Path) -> Report:
    return _manifest_rel(tmp, "docs%252Fguide.md")


def _manifest_percent_backslash(tmp: Path) -> Report:
    return _manifest_rel(tmp, "docs%5Cguide.md")


def _manifest_double_encoded_backslash(tmp: Path) -> Report:
    return _manifest_rel(tmp, "docs%255Cguide.md")


def _manifest_case_collision(tmp: Path) -> Report:
    return _manifest_report(_manifest_line("README.md", "a" * 64) + _manifest_line("readme.md", "b" * 64), tmp)


def _manifest_unicode_normalization_collision(tmp: Path) -> Report:
    nfd = unicodedata.normalize("NFD", "café") + ".txt"
    return _manifest_report(_manifest_line("café.txt", "a" * 64) + _manifest_line(nfd, "b" * 64), tmp)


def _generate_manifest_encoded_slash(tmp: Path) -> Report:
    root = tmp / "gen_encoded"
    root.mkdir()
    (root / "docs%2Fguide.md").write_text("x\n", encoding="utf-8")
    report = Report()
    try:
        generate_manifest(root)
    except Exception as exc:
        report.add(Issue(file=str(root), category="MANIFEST001: Artifact integrity", severity=Severity.HIGH, detector="encoded_collision_hardening_suite", description=str(exc), recommendation="Reject encoded separators during manifest generation."))
    return report


def _generate_manifest_case_collision(tmp: Path) -> Report:
    root = tmp / "gen_case"
    root.mkdir()
    (root / "README.md").write_text("a\n", encoding="utf-8")
    (root / "readme.md").write_text("b\n", encoding="utf-8")
    report = Report()
    try:
        generate_manifest(root)
    except Exception as exc:
        report.add(Issue(file=str(root), category="MANIFEST001: Artifact integrity", severity=Severity.HIGH, detector="encoded_collision_hardening_suite", description=str(exc), recommendation="Reject case-insensitive manifest collisions during generation."))
    return report


def _generate_manifest_unicode_collision(tmp: Path) -> Report:
    root = tmp / "gen_norm"
    root.mkdir()
    (root / "café.txt").write_text("a\n", encoding="utf-8")
    (root / (unicodedata.normalize("NFD", "café") + ".txt")).write_text("b\n", encoding="utf-8")
    report = Report()
    try:
        generate_manifest(root)
    except Exception as exc:
        report.add(Issue(file=str(root), category="MANIFEST001: Artifact integrity", severity=Severity.HIGH, detector="encoded_collision_hardening_suite", description=str(exc), recommendation="Reject Unicode-normalized manifest collisions during generation."))
    return report


def _markdown_encoded_slash_target(tmp: Path) -> Report:
    root = tmp / "md_encoded_slash"
    root.mkdir()
    (root / "README.md").write_text("[guide](docs%2Fguide.md)\n", encoding="utf-8")
    return audit_file_integrity(root)


def _zip_encoded_slash_member(tmp: Path) -> Report:
    archive = tmp / "encoded_slash.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/docs%2Fguide.md", "x\n")
        zf.writestr("pkg/README.md", "# ok\n")
    return audit_release(archive, run_cli_matrix=False)


def _zip_double_encoded_slash_member(tmp: Path) -> Report:
    archive = tmp / "double_encoded_slash.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/docs%252Fguide.md", "x\n")
        zf.writestr("pkg/README.md", "# ok\n")
    return audit_release(archive, run_cli_matrix=False)


def _zip_encoded_backslash_member(tmp: Path) -> Report:
    archive = tmp / "encoded_backslash.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/docs%5Cguide.md", "x\n")
        zf.writestr("pkg/README.md", "# ok\n")
    return audit_release(archive, run_cli_matrix=False)


def _yaml_duplicate_keys(tmp: Path) -> Report:
    root = tmp / "yaml_dup"
    root.mkdir()
    (root / "config.yaml").write_text("name: one\nname: two\n", encoding="utf-8")
    return audit_file_integrity(root)


def _yaml_list_item_no_false_positive(tmp: Path) -> Report:
    root = tmp / "yaml_list_ok"
    root.mkdir()
    (root / "workflow.yaml").write_text("jobs:\n  - name: one\n  - name: two\n", encoding="utf-8")
    observed = audit_file_integrity(root)
    report = Report()
    if any(issue.category.startswith("STRUCT007") for issue in observed.issues):
        return observed
    report.add(_ok_issue("yaml_list_item_no_false_positive", "YAML duplicate-key detector did not flag repeated keys across separate list items."))
    return report


def _ini_duplicate_option(tmp: Path) -> Report:
    root = tmp / "ini_dup_option"
    root.mkdir()
    (root / "setup.cfg").write_text("[tool]\nname = one\nname = two\n", encoding="utf-8")
    return audit_file_integrity(root)


def _ini_duplicate_section(tmp: Path) -> Report:
    root = tmp / "ini_dup_section"
    root.mkdir()
    (root / "setup.cfg").write_text("[tool]\nname = one\n[tool]\nname = two\n", encoding="utf-8")
    return audit_file_integrity(root)


def encoded_collision_hardening_cases() -> list[EncodedCollisionCase]:
    return [
        EncodedCollisionCase("manifest_percent_slash", "manifest rejects percent-encoded slash", "encoded_manifest_paths", ("MANIFEST001",), _manifest_percent_slash),
        EncodedCollisionCase("manifest_percent_slash_lower", "manifest rejects lowercase percent-encoded slash", "encoded_manifest_paths", ("MANIFEST001",), _manifest_percent_slash_lower),
        EncodedCollisionCase("manifest_double_encoded_slash", "manifest rejects double-encoded slash", "encoded_manifest_paths", ("MANIFEST001",), _manifest_double_encoded_slash),
        EncodedCollisionCase("manifest_percent_backslash", "manifest rejects percent-encoded backslash", "encoded_manifest_paths", ("MANIFEST001",), _manifest_percent_backslash),
        EncodedCollisionCase("manifest_double_encoded_backslash", "manifest rejects double-encoded backslash", "encoded_manifest_paths", ("MANIFEST001",), _manifest_double_encoded_backslash),
        EncodedCollisionCase("manifest_case_collision", "manifest rejects case-insensitive duplicate paths", "manifest_collisions", ("MANIFEST001",), _manifest_case_collision),
        EncodedCollisionCase("manifest_unicode_normalization_collision", "manifest rejects Unicode-normalized duplicate paths", "manifest_collisions", ("MANIFEST001",), _manifest_unicode_normalization_collision),
        EncodedCollisionCase("generate_manifest_encoded_slash", "manifest generator rejects encoded separators", "manifest_generation", ("MANIFEST001",), _generate_manifest_encoded_slash),
        EncodedCollisionCase("generate_manifest_case_collision", "manifest generator rejects case collisions", "manifest_generation", ("MANIFEST001",), _generate_manifest_case_collision),
        EncodedCollisionCase("generate_manifest_unicode_collision", "manifest generator rejects Unicode-normalized collisions", "manifest_generation", ("MANIFEST001",), _generate_manifest_unicode_collision),
        EncodedCollisionCase("markdown_encoded_slash_target", "Markdown rejects encoded slash targets", "markdown_encoded_targets", ("LINK001",), _markdown_encoded_slash_target),
        EncodedCollisionCase("zip_encoded_slash_member", "zip rejects percent-encoded slash members", "zip_encoded_members", ("ARCHIVE006",), _zip_encoded_slash_member),
        EncodedCollisionCase("zip_double_encoded_slash_member", "zip rejects double-encoded slash members", "zip_encoded_members", ("ARCHIVE006",), _zip_double_encoded_slash_member),
        EncodedCollisionCase("zip_encoded_backslash_member", "zip rejects percent-encoded backslash members", "zip_encoded_members", ("ARCHIVE006",), _zip_encoded_backslash_member),
        EncodedCollisionCase("yaml_duplicate_keys", "YAML-like duplicate mapping keys are rejected", "structured_duplicates", ("STRUCT007",), _yaml_duplicate_keys),
        EncodedCollisionCase("yaml_list_item_no_false_positive", "YAML duplicate-key check allows repeated keys across list items", "structured_false_positive_guards", ("ENCCOLL_OK",), _yaml_list_item_no_false_positive),
        EncodedCollisionCase("ini_duplicate_option", "INI duplicate options are rejected", "structured_duplicates", ("STRUCT008",), _ini_duplicate_option),
        EncodedCollisionCase("ini_duplicate_section", "INI duplicate sections are rejected", "structured_duplicates", ("STRUCT008",), _ini_duplicate_section),
    ]


def run_encoded_collision_hardening_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-encoded-collision-") as tmp_s:
        base = Path(tmp_s)
        for case in encoded_collision_hardening_cases():
            case_dir = base / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            try:
                observed = case.runner(case_dir)
            except Exception as exc:
                report.add(Issue(
                    file=f"<encoded-collision:{case.case_id}>",
                    category="ENCCOLL002: Encoded/collision fixture crash",
                    severity=Severity.HIGH,
                    detector="encoded_collision_hardening_suite",
                    description=f"Encoded/collision fixture crashed: {exc}",
                    recommendation="Fix the fixture or the underlying detector.",
                ))
                continue
            if observed.skipped_files:
                report.record_skip(
                    f"<encoded-collision:{case.case_id}>",
                    "; ".join(item.get("reason", "skipped") for item in observed.skipped_files),
                )
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(_suite_issue(case, _categories(observed)))
    return report


def encoded_collision_hardening_suite_summary() -> dict[str, object]:
    cases = encoded_collision_hardening_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "case_count": len(cases),
        "families": dict(sorted(families.items())),
        "threat_classes": [
            "percent_encoded_and_double_encoded_path_separators",
            "manifest_case_and_unicode_normalized_collisions",
            "manifest_generation_collision_consistency",
            "encoded_markdown_targets",
            "encoded_zip_member_names",
            "yaml_ini_duplicate_keys",
            "structured_file_false_positive_guards",
        ],
        "cases": [
            {"case_id": c.case_id, "family": c.family, "title": c.title, "expected_prefixes": list(c.expected_prefixes)}
            for c in cases
        ],
    }


def write_encoded_collision_hardening_summary(path: str | Path | None) -> None:
    """Write the encoded/collision fixture inventory.

    Returns None when no output path is provided.
    """
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(encoded_collision_hardening_suite_summary(), ensure_ascii=False, indent=2), encoding="utf-8")
