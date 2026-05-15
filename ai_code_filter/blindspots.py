from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Iterable

from .integrity import MANIFEST_NAME, audit_file_integrity, parse_manifest, verify_manifest, write_manifest
from .models import Issue, Report, Severity
from .release.audit import audit_release


@dataclass(frozen=True)
class BlindSpotCase:
    """A regression fixture for previously missed acceptance/audit edge cases."""

    case_id: str
    title: str
    family: str
    expected_prefixes: tuple[str, ...]
    runner: Callable[[Path], Report]


def _issue(case: BlindSpotCase, observed: Iterable[str]) -> Issue:
    observed_s = ", ".join(sorted(observed)) or "<none>"
    expected_s = ", ".join(case.expected_prefixes)
    return Issue(
        file=f"<blindspot:{case.case_id}>",
        category="BLINDSPOT001: Blind-spot regression failure",
        severity=Severity.HIGH,
        detector="blindspot_suite",
        description=(
            f"Blind-spot fixture was not detected: {case.title}. "
            f"Expected one of [{expected_s}], observed [{observed_s}]."
        ),
        recommendation="Add or repair the detector and keep this blind-spot fixture in the release acceptance suite.",
    )


def _categories(report: Report) -> set[str]:
    return {issue.category.split(":", 1)[0] for issue in report.issues}


def _has_expected(report: Report, prefixes: tuple[str, ...]) -> bool:
    categories = _categories(report)
    return any(any(category.startswith(prefix) for category in categories) for prefix in prefixes)


def _report_from_manifest_text(text: str, tmp: Path) -> Report:
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
            detector="blindspot_suite",
            description=str(exc),
            recommendation="Reject malformed or ambiguous manifests.",
        ))
    return report


def _minimal_release(root: Path, version: str = "0.30.0") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "ai_code_filter").mkdir(exist_ok=True)
    (root / "tests").mkdir(exist_ok=True)
    (root / "ai_filter.py").write_text("from ai_code_filter.cli import main\nraise SystemExit(main())\n", encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "README.md").write_text(f"# Mini Release v0.30\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "mini-release"\nversion = "{version}"\ndependencies = []\n[project.scripts]\nai-code-filter = "ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    (root / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
    write_manifest(root)
    return root


def _manifest_windows_drive(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  C:/evil.txt  size=1\n", tmp)


def _manifest_double_space_path(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  dir/two  spaces.txt  size=1\n", tmp)


def _manifest_leading_space_path(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}   leading.txt  size=1\n", tmp)


def _manifest_trailing_space_path(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  trailing.txt   size=1\n", tmp)


def _manifest_backslash_path(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  dir\\evil.txt  size=1\n", tmp)


def _manifest_traversal_path(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  dir/../evil.txt  size=1\n", tmp)


def _verify_manifest_symlink_entry(tmp: Path) -> Report:
    root = tmp / "release"
    root.mkdir()
    outside = tmp / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    link = root / "linked.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        report = Report()
        report.record_skip("<symlink>", "symlinks unsupported")
        return report
    manifest = tmp / MANIFEST_NAME
    manifest.write_text(f"{'a'*64}  linked.txt  size=8\n", encoding="utf-8")
    return verify_manifest(root, manifest)


def _generate_manifest_ignores_external_symlink(tmp: Path) -> Report:
    root = tmp / "release"
    root.mkdir()
    (root / "regular.txt").write_text("ok\n", encoding="utf-8")
    outside = tmp / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        (root / "outside.txt").symlink_to(outside)
    except (OSError, NotImplementedError):
        report = Report(); report.record_skip("<symlink>", "symlinks unsupported"); return report
    write_manifest(root)
    report = verify_manifest(root, root / MANIFEST_NAME)
    # A correct generator must not follow symlinks. If it did, verify would pass but manifest would contain the link.
    manifest_text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    if "outside.txt" in manifest_text:
        report.add(Issue(file=str(root / MANIFEST_NAME), category="BLINDSPOT002: Manifest generator followed symlink", severity=Severity.HIGH, detector="blindspot_suite", description="Manifest generator included a symlink-backed path.", recommendation="Skip symlinks while generating manifests."))
    else:
        report.add(Issue(file=str(root / MANIFEST_NAME), category="BLINDSPOT_OK: Manifest generator skipped symlink", severity=Severity.LOW, detector="blindspot_suite", description="Manifest generator did not include symlink-backed path.", recommendation="No action."))
    return report


def _tree_git_noise(tmp: Path) -> Report:
    root = tmp / "tree_git"; root.mkdir(); (root / ".git").mkdir(); (root / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_venv_noise(tmp: Path) -> Report:
    root = tmp / "tree_venv"; root.mkdir(); (root / ".venv").mkdir(); (root / ".venv" / "pyvenv.cfg").write_text("x\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_node_modules_noise(tmp: Path) -> Report:
    root = tmp / "tree_node"; root.mkdir(); (root / "node_modules").mkdir(); (root / "node_modules" / "pkg.js").write_text("x\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_dist_noise(tmp: Path) -> Report:
    root = tmp / "tree_dist"; root.mkdir(); (root / "dist").mkdir(); (root / "dist" / "artifact.whl").write_bytes(b"wheel")
    return audit_file_integrity(root)


def _tree_rst_truncation(tmp: Path) -> Report:
    root = tmp / "tree_rst"; root.mkdir(); (root / "README.rst").write_text("Heading\n=======", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_directory_case_collision(tmp: Path) -> Report:
    root = tmp / "tree_case_dirs"; root.mkdir(); (root / "Docs").mkdir(); (root / "docs").mkdir(); (root / "Docs" / "a.txt").write_text("a\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_markdown_windows_drive_link(tmp: Path) -> Report:
    root = tmp / "tree_md_drive"; root.mkdir(); (root / "README.md").write_text("[bad](C:/tmp/file.md)\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_markdown_backslash_link(tmp: Path) -> Report:
    root = tmp / "tree_md_backslash"; root.mkdir(); (root / "README.md").write_text(r"[bad](docs\\file.md)" + "\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_markdown_reference_with_spaces(tmp: Path) -> Report:
    root = tmp / "tree_md_ref_spaces"; root.mkdir(); (root / "docs").mkdir(); (root / "docs" / "guide.md").write_text("ok\n", encoding="utf-8")
    (root / "README.md").write_text('[Guide][g]\n\n[g]: docs/guide.md "Guide title"\n', encoding="utf-8")
    report = audit_file_integrity(root)
    # This is a false-positive guard: no LINKREF002 missing-target finding should be emitted.
    if any(issue.category.startswith("LINKREF002") for issue in report.issues):
        report.add(Issue(file="README.md", category="BLINDSPOT003: Markdown reference false positive", severity=Severity.HIGH, detector="blindspot_suite", description="Reference-style Markdown link with title was misclassified as missing.", recommendation="Parse Markdown reference target titles correctly."))
    else:
        report.add(Issue(file="README.md", category="BLINDSPOT_OK: Markdown reference with spaces", severity=Severity.LOW, detector="blindspot_suite", description="Markdown reference-style link with title is accepted.", recommendation="No action."))
    return report


def _release_directory_name_mismatch(tmp: Path) -> Report:
    root = _minimal_release(tmp / "ai_code_filter_refactored_v99")
    return audit_release(root, run_cli_matrix=False)


def _release_pyproject_tool_version_confusion(tmp: Path) -> Report:
    root = _minimal_release(tmp / "ai_code_filter_refactored_v30")
    (root / "pyproject.toml").write_text(
        '[tool.fake]\nversion = "9.9.9"\n[project]\nname = "mini-release"\nversion = "0.30.0"\ndependencies = []\n[project.scripts]\nai-code-filter = "ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    write_manifest(root)
    report = audit_release(root, run_cli_matrix=False)
    if any(issue.category.startswith("REL003") for issue in report.issues):
        report.add(Issue(file="pyproject.toml", category="BLINDSPOT004: Pyproject parser selected tool version", severity=Severity.HIGH, detector="blindspot_suite", description="pyproject parser confused [tool.*].version with [project].version.", recommendation="Parse TOML structurally, not with a global version regex."))
    else:
        report.add(Issue(file="pyproject.toml", category="BLINDSPOT_OK: Pyproject structural version", severity=Severity.LOW, detector="blindspot_suite", description="pyproject parser selected [project].version.", recommendation="No action."))
    return report


def _release_openai_optional_only(tmp: Path) -> Report:
    root = _minimal_release(tmp / "ai_code_filter_refactored_v30")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "mini-release"\nversion = "0.30.0"\ndependencies = []\n[project.optional-dependencies]\nai = ["openai>=1.0.0"]\n[project.scripts]\nai-code-filter = "ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    write_manifest(root)
    report = audit_release(root, run_cli_matrix=False)
    if any(issue.category.startswith("REL006") for issue in report.issues):
        report.add(Issue(file="pyproject.toml", category="BLINDSPOT005: Optional OpenAI dependency misclassified", severity=Severity.HIGH, detector="blindspot_suite", description="Optional OpenAI dependency was treated as mandatory.", recommendation="Only inspect [project].dependencies for mandatory OpenAI dependency checks."))
    else:
        report.add(Issue(file="pyproject.toml", category="BLINDSPOT_OK: Optional OpenAI accepted", severity=Severity.LOW, detector="blindspot_suite", description="Optional OpenAI dependency is accepted.", recommendation="No action."))
    return report


def _release_console_script_comment_only(tmp: Path) -> Report:
    root = _minimal_release(tmp / "ai_code_filter_refactored_v30")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "mini-release"\nversion = "0.30.0"\ndependencies = []\n# ai-code-filter = "ai_code_filter.cli:main"\n[project.scripts]\nother = "x:y"\n',
        encoding="utf-8",
    )
    write_manifest(root)
    return audit_release(root, run_cli_matrix=False)


def _zip_duplicate_member(tmp: Path) -> Report:
    zp = tmp / "dup.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("pkg/a.txt", b"1")
        zf.writestr("pkg/a.txt", b"2")
    return audit_release(zp, run_cli_matrix=False)


def _zip_windows_drive_member(tmp: Path) -> Report:
    zp = tmp / "drive.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("C:/evil.txt", b"x")
    return audit_release(zp, run_cli_matrix=False)


def _zip_backslash_member(tmp: Path) -> Report:
    zp = tmp / "backslash.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr(r"pkg\\evil.txt", b"x")
    return audit_release(zp, run_cli_matrix=False)


def _zip_control_char_member(tmp: Path) -> Report:
    zp = tmp / "control.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("pkg/bad\x01name.txt", b"x")
    return audit_release(zp, run_cli_matrix=False)



def _manifest_reserved_windows_name(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  CON.txt  size=1\n", tmp)


def _manifest_colon_ads_path(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  dir/file:stream.txt  size=1\n", tmp)


def _manifest_trailing_dot_path(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  dir/trailingdot.  size=1\n", tmp)


def _manifest_percent_encoded_traversal(tmp: Path) -> Report:
    return _report_from_manifest_text(f"{'a'*64}  dir/%2e%2e/evil.txt  size=1\n", tmp)


def _tree_reserved_windows_name(tmp: Path) -> Report:
    root = tmp / "tree_reserved"; root.mkdir(); (root / "CON.txt").write_text("x\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_colon_ads_name(tmp: Path) -> Report:
    root = tmp / "tree_colon"; root.mkdir(); (root / "file:stream.txt").write_text("x\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_unicode_format_name(tmp: Path) -> Report:
    root = tmp / "tree_bidi"; root.mkdir(); (root / "bad\u202ename.txt").write_text("x\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_markdown_percent_traversal(tmp: Path) -> Report:
    root = tmp / "tree_md_pct"; root.mkdir(); (root / "docs").mkdir(); (root / "README.md").write_text("[x](docs/%2e%2e/secret.md)\n", encoding="utf-8")
    return audit_file_integrity(root)


def _zip_reserved_windows_member(tmp: Path) -> Report:
    zp = tmp / "reserved.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("pkg/CON.txt", b"x")
    return audit_release(zp, run_cli_matrix=False)


def _zip_colon_ads_member(tmp: Path) -> Report:
    zp = tmp / "ads.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("pkg/file:stream.txt", b"x")
    return audit_release(zp, run_cli_matrix=False)


def _zip_double_slash_member(tmp: Path) -> Report:
    zp = tmp / "doubleslash.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("pkg/a//b.txt", b"x")
    return audit_release(zp, run_cli_matrix=False)


def _zip_case_insensitive_duplicate_member(tmp: Path) -> Report:
    zp = tmp / "case-dup.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("pkg/README.md", b"a")
        zf.writestr("pkg/readme.md", b"b")
    return audit_release(zp, run_cli_matrix=False)

def blindspot_cases() -> list[BlindSpotCase]:
    return [
        BlindSpotCase("manifest_windows_drive", "manifest rejects Windows-drive paths", "manifest_path_parsing", ("MANIFEST001",), _manifest_windows_drive),
        BlindSpotCase("manifest_double_space_path", "manifest rejects ambiguous double-space path format", "manifest_path_parsing", ("MANIFEST001",), _manifest_double_space_path),
        BlindSpotCase("manifest_leading_space_path", "manifest rejects leading whitespace in paths", "manifest_path_parsing", ("MANIFEST001",), _manifest_leading_space_path),
        BlindSpotCase("manifest_trailing_space_path", "manifest rejects trailing whitespace in paths", "manifest_path_parsing", ("MANIFEST001",), _manifest_trailing_space_path),
        BlindSpotCase("manifest_backslash_path", "manifest rejects backslash paths", "manifest_path_parsing", ("MANIFEST001",), _manifest_backslash_path),
        BlindSpotCase("manifest_traversal_path", "manifest rejects nested traversal components", "manifest_path_parsing", ("MANIFEST001",), _manifest_traversal_path),
        BlindSpotCase("verify_manifest_symlink_entry", "manifest verifier rejects symlink-backed entries", "manifest_verification", ("MANIFEST006",), _verify_manifest_symlink_entry),
        BlindSpotCase("generate_manifest_external_symlink", "manifest generator must not include external symlink", "manifest_verification", ("BLINDSPOT_OK",), _generate_manifest_ignores_external_symlink),
        BlindSpotCase("tree_git_noise", "integrity audit flags .git directories", "release_noise", ("HYGIENE002",), _tree_git_noise),
        BlindSpotCase("tree_venv_noise", "integrity audit flags .venv directories", "release_noise", ("HYGIENE002",), _tree_venv_noise),
        BlindSpotCase("tree_node_modules_noise", "integrity audit flags node_modules", "release_noise", ("HYGIENE002",), _tree_node_modules_noise),
        BlindSpotCase("tree_dist_noise", "integrity audit flags dist/build artifacts", "release_noise", ("HYGIENE002",), _tree_dist_noise),
        BlindSpotCase("tree_rst_truncation", "integrity audit covers .rst truncation/newline normalization", "text_integrity", ("TRUNC001",), _tree_rst_truncation),
        BlindSpotCase("tree_directory_case_collision", "integrity audit catches directory case collisions", "path_collisions", ("PATH001",), _tree_directory_case_collision),
        BlindSpotCase("markdown_windows_drive_link", "Markdown Windows-drive links are unsafe", "markdown_links", ("LINK001",), _tree_markdown_windows_drive_link),
        BlindSpotCase("markdown_backslash_link", "Markdown backslash links are unsafe", "markdown_links", ("LINK001",), _tree_markdown_backslash_link),
        BlindSpotCase("markdown_reference_with_spaces", "Markdown reference links with titles do not false-positive", "markdown_links", ("BLINDSPOT_OK",), _tree_markdown_reference_with_spaces),
        BlindSpotCase("release_directory_name_mismatch", "directory releases also validate versioned root names", "release_metadata", ("ARCHIVE001",), _release_directory_name_mismatch),
        BlindSpotCase("pyproject_tool_version_confusion", "pyproject parser uses [project].version only", "release_metadata", ("BLINDSPOT_OK",), _release_pyproject_tool_version_confusion),
        BlindSpotCase("openai_optional_only", "optional OpenAI dependency is not mandatory", "dependency_contract", ("BLINDSPOT_OK",), _release_openai_optional_only),
        BlindSpotCase("console_script_comment_only", "console script check ignores comments", "release_metadata", ("REL005",), _release_console_script_comment_only),
        BlindSpotCase("zip_duplicate_member", "zip duplicate members are rejected", "zip_integrity", ("ARCHIVE011",), _zip_duplicate_member),
        BlindSpotCase("zip_windows_drive_member", "zip Windows-drive members are unsafe", "zip_integrity", ("ARCHIVE006",), _zip_windows_drive_member),
        BlindSpotCase("zip_backslash_member", "zip backslash members are unsafe", "zip_integrity", ("ARCHIVE006",), _zip_backslash_member),
        BlindSpotCase("zip_control_char_member", "zip control-character members are unsafe", "zip_integrity", ("ARCHIVE006",), _zip_control_char_member),
        BlindSpotCase("manifest_reserved_windows_name", "manifest rejects reserved Windows names", "path_portability", ("MANIFEST001",), _manifest_reserved_windows_name),
        BlindSpotCase("manifest_colon_ads_path", "manifest rejects ADS-style colon paths", "path_portability", ("MANIFEST001",), _manifest_colon_ads_path),
        BlindSpotCase("manifest_trailing_dot_path", "manifest rejects trailing-dot components", "path_portability", ("MANIFEST001",), _manifest_trailing_dot_path),
        BlindSpotCase("manifest_percent_encoded_traversal", "manifest rejects percent-encoded traversal", "path_portability", ("MANIFEST001",), _manifest_percent_encoded_traversal),
        BlindSpotCase("tree_reserved_windows_name", "tree integrity flags reserved Windows names", "path_portability", ("PATH003",), _tree_reserved_windows_name),
        BlindSpotCase("tree_colon_ads_name", "tree integrity flags ADS-style colon names", "path_portability", ("PATH003",), _tree_colon_ads_name),
        BlindSpotCase("tree_unicode_format_name", "tree integrity flags Unicode format-control names", "path_portability", ("PATH003",), _tree_unicode_format_name),
        BlindSpotCase("markdown_percent_traversal", "Markdown validator rejects percent-encoded traversal", "path_portability", ("LINK001",), _tree_markdown_percent_traversal),
        BlindSpotCase("zip_reserved_windows_member", "zip rejects reserved Windows names", "path_portability", ("ARCHIVE006",), _zip_reserved_windows_member),
        BlindSpotCase("zip_colon_ads_member", "zip rejects ADS-style colon names", "path_portability", ("ARCHIVE006",), _zip_colon_ads_member),
        BlindSpotCase("zip_double_slash_member", "zip rejects double-slash members", "path_portability", ("ARCHIVE006",), _zip_double_slash_member),
        BlindSpotCase("zip_case_insensitive_duplicate_member", "zip detects case-insensitive duplicate members", "path_portability", ("ARCHIVE014",), _zip_case_insensitive_duplicate_member),
    ]


def run_blindspot_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-blindspots-") as tmp_s:
        base = Path(tmp_s)
        for case in blindspot_cases():
            case_dir = base / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            try:
                observed = case.runner(case_dir)
            except Exception as exc:
                report.add(Issue(file=f"<blindspot:{case.case_id}>", category="BLINDSPOT002: Blind-spot fixture crash", severity=Severity.HIGH, detector="blindspot_suite", description=f"Blind-spot fixture crashed: {exc}", recommendation="Fix the blind-spot fixture or underlying detector."))
                continue
            if observed.skipped_files:
                report.record_skip(f"<blindspot:{case.case_id}>", "; ".join(item.get("reason", "skipped") for item in observed.skipped_files))
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(_issue(case, _categories(observed)))
    return report


def blindspot_suite_summary() -> dict[str, object]:
    cases = blindspot_cases()
    families: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
    return {
        "case_count": len(cases),
        "families": dict(sorted(families.items())),
        "cases": [
            {"case_id": c.case_id, "family": c.family, "title": c.title, "expected_prefixes": list(c.expected_prefixes)}
            for c in cases
        ],
    }


def write_blindspot_summary(path: str | Path | None) -> None:
    """Write the blind-spot inventory and return None when no path is provided."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(blindspot_suite_summary(), ensure_ascii=False, indent=2), encoding="utf-8")
