from __future__ import annotations

import json
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Iterable

from .integrity import MANIFEST_NAME, audit_file_integrity, parse_manifest
from .models import Issue, Report, Severity
from .release.audit import audit_release


@dataclass(frozen=True)
class StructuredHardeningCase:
    """Regression fixture for structured-file and Unicode/path-confusable hardening."""

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


def _suite_issue(case: StructuredHardeningCase, observed: Iterable[str]) -> Issue:
    observed_s = ", ".join(sorted(observed)) or "<none>"
    expected_s = ", ".join(case.expected_prefixes)
    return Issue(
        file=f"<structured-hardening:{case.case_id}>",
        category="STRUCTHARD001: Structured hardening regression failure",
        severity=Severity.HIGH,
        detector="structured_hardening_suite",
        description=(
            f"Structured/unicode hardening fixture was not detected: {case.title}. "
            f"Expected one of [{expected_s}], observed [{observed_s}]."
        ),
        recommendation="Add or repair the structured-file/path-confusable detector and keep this fixture enabled.",
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
            detector="structured_hardening_suite",
            description=str(exc),
            recommendation="Reject malformed, ambiguous or non-portable manifest paths.",
        ))
    return report


def _manifest_rel(tmp: Path, rel: str) -> Report:
    return _manifest_report(f"{'a'*64}  {rel}  size=1\n", tmp)


# Manifest/path-confusable cases from the v30 external audit class.
def _manifest_home(tmp: Path) -> Report:
    return _manifest_rel(tmp, "~/evil.txt")


def _manifest_fullwidth_slash(tmp: Path) -> Report:
    return _manifest_rel(tmp, "safe／evil.txt")


def _manifest_division_slash(tmp: Path) -> Report:
    return _manifest_rel(tmp, "safe∕evil.txt")


def _manifest_fraction_slash(tmp: Path) -> Report:
    return _manifest_rel(tmp, "safe⁄evil.txt")


def _manifest_superscript_device(tmp: Path) -> Report:
    return _manifest_rel(tmp, "COM¹.txt")


def _tree_with_names(tmp: Path, names: list[str]) -> Report:
    root = tmp / "tree"
    root.mkdir()
    for name in names:
        (root / name).write_text("x\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_home_like(tmp: Path) -> Report:
    return _tree_with_names(tmp, ["~evil.txt"])


def _tree_fullwidth_slash(tmp: Path) -> Report:
    return _tree_with_names(tmp, ["safe／evil.txt"])


def _tree_division_slash(tmp: Path) -> Report:
    return _tree_with_names(tmp, ["safe∕evil.txt"])


def _tree_fraction_slash(tmp: Path) -> Report:
    return _tree_with_names(tmp, ["safe⁄evil.txt"])


def _tree_superscript_device(tmp: Path) -> Report:
    return _tree_with_names(tmp, ["COM¹.txt"])


def _tree_unicode_normalization_collision(tmp: Path) -> Report:
    root = tmp / "norm_collision"
    root.mkdir()
    (root / "café.txt").write_text("a\n", encoding="utf-8")
    (root / (unicodedata.normalize("NFD", "café") + ".txt")).write_text("b\n", encoding="utf-8")
    return audit_file_integrity(root)


# Structured text hardening.
def _json_duplicate_keys(tmp: Path) -> Report:
    root = tmp / "json_dup"
    root.mkdir()
    (root / "report.json").write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
    return audit_file_integrity(root)


def _xml_doctype(tmp: Path) -> Report:
    root = tmp / "xml_doctype"
    root.mkdir()
    (root / "report.xml").write_text("<!DOCTYPE x><x/>\n", encoding="utf-8")
    return audit_file_integrity(root)


def _xml_entity(tmp: Path) -> Report:
    root = tmp / "xml_entity"
    root.mkdir()
    (root / "report.xml").write_text("<!ENTITY x 'y'><x/>\n", encoding="utf-8")
    return audit_file_integrity(root)


def _markdown_html_href(tmp: Path) -> Report:
    root = tmp / "md_href"
    root.mkdir()
    (root / "README.md").write_text('<a href="missing.md">x</a>\n', encoding="utf-8")
    return audit_file_integrity(root)


def _markdown_html_src(tmp: Path) -> Report:
    root = tmp / "md_src"
    root.mkdir()
    (root / "README.md").write_text('<img src="missing.png">\n', encoding="utf-8")
    return audit_file_integrity(root)


# Zip directory/member hardening.
def _zip_unsafe_directory(tmp: Path) -> Report:
    archive = tmp / "unsafe_dir.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/../evil/", "")
        zf.writestr("pkg/README.md", "# ok\n")
    return audit_release(archive, run_cli_matrix=False)


def _zip_duplicate_directory(tmp: Path) -> Report:
    archive = tmp / "dup_dir.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/docs/", "")
        zf.writestr("pkg/docs/", "")
        zf.writestr("pkg/README.md", "# ok\n")
    return audit_release(archive, run_cli_matrix=False)


def _zip_case_duplicate_directory(tmp: Path) -> Report:
    archive = tmp / "case_dup_dir.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/DOCS/", "")
        zf.writestr("pkg/docs/", "")
        zf.writestr("pkg/README.md", "# ok\n")
    return audit_release(archive, run_cli_matrix=False)


def _zip_unicode_normalization_duplicate(tmp: Path) -> Report:
    archive = tmp / "norm_dup.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/café.txt", "a")
        zf.writestr(f"pkg/{unicodedata.normalize('NFD', 'café')}.txt", "b")
    return audit_release(archive, run_cli_matrix=False)


# Release hygiene hardening from OS-generated trash files.
def _tree_ds_store(tmp: Path) -> Report:
    root = tmp / "trash_ds"
    root.mkdir()
    (root / ".DS_Store").write_text("trash\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_thumbs_db(tmp: Path) -> Report:
    root = tmp / "trash_thumbs"
    root.mkdir()
    (root / "Thumbs.db").write_text("trash\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_desktop_ini(tmp: Path) -> Report:
    root = tmp / "trash_desktop"
    root.mkdir()
    (root / "desktop.ini").write_text("trash\n", encoding="utf-8")
    return audit_file_integrity(root)


def structured_hardening_cases() -> list[StructuredHardeningCase]:
    return [
        StructuredHardeningCase("manifest_home_shorthand", "manifest rejects ~/ paths", "manifest_path_confusables", ("MANIFEST001",), _manifest_home),
        StructuredHardeningCase("manifest_fullwidth_slash", "manifest rejects fullwidth slash", "manifest_path_confusables", ("MANIFEST001",), _manifest_fullwidth_slash),
        StructuredHardeningCase("manifest_division_slash", "manifest rejects division slash", "manifest_path_confusables", ("MANIFEST001",), _manifest_division_slash),
        StructuredHardeningCase("manifest_fraction_slash", "manifest rejects fraction slash", "manifest_path_confusables", ("MANIFEST001",), _manifest_fraction_slash),
        StructuredHardeningCase("manifest_superscript_device", "manifest rejects superscript Windows device names", "manifest_path_confusables", ("MANIFEST001",), _manifest_superscript_device),
        StructuredHardeningCase("tree_home_like", "tree integrity rejects home-like names", "tree_path_confusables", ("PATH003",), _tree_home_like),
        StructuredHardeningCase("tree_fullwidth_slash", "tree integrity rejects fullwidth slash-like names", "tree_path_confusables", ("PATH003",), _tree_fullwidth_slash),
        StructuredHardeningCase("tree_division_slash", "tree integrity rejects division slash-like names", "tree_path_confusables", ("PATH003",), _tree_division_slash),
        StructuredHardeningCase("tree_fraction_slash", "tree integrity rejects fraction slash-like names", "tree_path_confusables", ("PATH003",), _tree_fraction_slash),
        StructuredHardeningCase("tree_superscript_device", "tree integrity rejects superscript Windows device names", "tree_path_confusables", ("PATH003",), _tree_superscript_device),
        StructuredHardeningCase("tree_unicode_normalization_collision", "tree integrity rejects Unicode-normalized collisions", "unicode_normalization", ("PATH004",), _tree_unicode_normalization_collision),
        StructuredHardeningCase("json_duplicate_keys", "JSON duplicate keys are rejected", "structured_text", ("STRUCT001",), _json_duplicate_keys),
        StructuredHardeningCase("xml_doctype", "XML DOCTYPE is rejected", "structured_text", ("STRUCT006",), _xml_doctype),
        StructuredHardeningCase("xml_entity", "XML ENTITY is rejected", "structured_text", ("STRUCT006",), _xml_entity),
        StructuredHardeningCase("markdown_html_href", "Markdown HTML href links are checked", "markdown_embedded_html", ("LINKHTML002",), _markdown_html_href),
        StructuredHardeningCase("markdown_html_src", "Markdown HTML src links are checked", "markdown_embedded_html", ("LINKHTML002",), _markdown_html_src),
        StructuredHardeningCase("zip_unsafe_directory", "zip unsafe directory entries are rejected", "zip_directory_integrity", ("ARCHIVE006",), _zip_unsafe_directory),
        StructuredHardeningCase("zip_duplicate_directory", "zip duplicate directory entries are rejected", "zip_directory_integrity", ("ARCHIVE011",), _zip_duplicate_directory),
        StructuredHardeningCase("zip_case_duplicate_directory", "zip case-insensitive directory duplicates are rejected", "zip_directory_integrity", ("ARCHIVE014",), _zip_case_duplicate_directory),
        StructuredHardeningCase("zip_unicode_normalization_duplicate", "zip Unicode-normalized duplicate members are rejected", "zip_directory_integrity", ("ARCHIVE015",), _zip_unicode_normalization_duplicate),
        StructuredHardeningCase("tree_ds_store", ".DS_Store release trash is rejected", "release_noise", ("HYGIENE002",), _tree_ds_store),
        StructuredHardeningCase("tree_thumbs_db", "Thumbs.db release trash is rejected", "release_noise", ("HYGIENE002",), _tree_thumbs_db),
        StructuredHardeningCase("tree_desktop_ini", "desktop.ini release trash is rejected", "release_noise", ("HYGIENE002",), _tree_desktop_ini),
    ]


def run_structured_hardening_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-structured-hardening-") as tmp_s:
        base = Path(tmp_s)
        for case in structured_hardening_cases():
            case_dir = base / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            try:
                observed = case.runner(case_dir)
            except Exception as exc:
                report.add(Issue(
                    file=f"<structured-hardening:{case.case_id}>",
                    category="STRUCTHARD002: Structured hardening fixture crash",
                    severity=Severity.HIGH,
                    detector="structured_hardening_suite",
                    description=f"Structured hardening fixture crashed: {exc}",
                    recommendation="Fix the fixture or the underlying detector.",
                ))
                continue
            if observed.skipped_files:
                report.record_skip(
                    f"<structured-hardening:{case.case_id}>",
                    "; ".join(item.get("reason", "skipped") for item in observed.skipped_files),
                )
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(_suite_issue(case, _categories(observed)))
    return report


def structured_hardening_suite_summary() -> dict[str, object]:
    cases = structured_hardening_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "case_count": len(cases),
        "families": dict(sorted(families.items())),
        "threat_classes": [
            "unicode_slash_and_path_confusables",
            "home_shorthand_paths",
            "superscript_windows_device_names",
            "unicode_normalization_collisions",
            "structured_file_parser_hardening",
            "markdown_embedded_html_links",
            "zip_directory_entry_integrity",
            "os_generated_release_trash",
        ],
        "cases": [
            {"case_id": c.case_id, "family": c.family, "title": c.title, "expected_prefixes": list(c.expected_prefixes)}
            for c in cases
        ],
    }


def write_structured_hardening_summary(path: str | Path | None) -> None:
    """Write the structured-hardening fixture inventory.

    Returns None when no output path is provided.
    """
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(structured_hardening_suite_summary(), ensure_ascii=False, indent=2), encoding="utf-8")
