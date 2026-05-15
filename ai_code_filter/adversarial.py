from __future__ import annotations

import json
import os
import stat
import zipfile
import warnings
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Iterable

from .integrity import MANIFEST_NAME, audit_file_integrity, manifest_text, parse_manifest, verify_manifest, write_manifest
from .models import Issue, Report, Severity
from .release.audit import audit_release


@dataclass(frozen=True)
class AdversarialCase:
    case_id: str
    title: str
    expected_prefixes: tuple[str, ...]
    runner: Callable[[Path], Report]


def _issue(case_id: str, title: str, expected: Iterable[str], observed: Iterable[str]) -> Issue:
    exp = ", ".join(expected)
    obs = ", ".join(sorted(observed)) or "<none>"
    return Issue(
        file=f"<adversarial:{case_id}>",
        category="ADV001: Adversarial acceptance failure",
        severity=Severity.HIGH,
        detector="adversarial_suite",
        description=f"Adversarial fixture was not detected: {title}. Expected one of [{exp}], observed [{obs}].",
        recommendation="Add or repair the detector/regression test for this adversarial release fixture.",
    )


def _categories(report: Report) -> set[str]:
    cats: set[str] = set()
    for issue in report.issues:
        cats.add(issue.category.split(":", 1)[0])
    return cats


def _has_expected(report: Report, prefixes: tuple[str, ...]) -> bool:
    cats = _categories(report)
    return any(any(cat.startswith(prefix) for cat in cats) for prefix in prefixes)


def _minimal_project(root: Path, version: str = "0.30.0") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "ai_code_filter").mkdir(exist_ok=True)
    (root / "tests").mkdir(exist_ok=True)
    (root / "ai_filter.py").write_text("from ai_code_filter.cli import main\nraise SystemExit(main())\n", encoding="utf-8")
    (root / "ai_code_filter" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "README.md").write_text(f"# Test Project v0.30\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname="x"\nversion = "{version}"\n[project.scripts]\nai-code-filter = "ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    (root / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
    write_manifest(root)
    return root


def _zip_tree(root: Path, zip_path: Path, arc_root: str | None = None) -> Path:
    base_name = arc_root or root.name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                zf.write(path, f"{base_name}/{path.relative_to(root).as_posix()}")
    return zip_path


def _manifest_report(text: str, tmp: Path) -> Report:
    manifest = tmp / "MANIFEST.sha256"
    manifest.write_text(text, encoding="utf-8")
    report = Report()
    try:
        parse_manifest(manifest)
    except Exception as exc:
        report.add(Issue(file=str(manifest), category="MANIFEST001: Artifact integrity", severity=Severity.CRITICAL, detector="adversarial_suite", description=str(exc), recommendation="Reject unsafe manifests."))
    return report


def _manifest_duplicate(tmp: Path) -> Report:
    good = "a" * 64
    return _manifest_report(f"{good}  a.txt  size=1\n{good}  a.txt  size=1\n", tmp)


def _manifest_negative_size(tmp: Path) -> Report:
    return _manifest_report(f"{'a'*64}  a.txt  size=-1\n", tmp)


def _manifest_non_integer_size(tmp: Path) -> Report:
    return _manifest_report(f"{'a'*64}  a.txt  size=one\n", tmp)


def _manifest_absolute_path(tmp: Path) -> Report:
    return _manifest_report(f"{'a'*64}  /etc/passwd  size=1\n", tmp)


def _manifest_traversal(tmp: Path) -> Report:
    return _manifest_report(f"{'a'*64}  ../evil.txt  size=1\n", tmp)


def _manifest_backslash(tmp: Path) -> Report:
    return _manifest_report(f"{'a'*64}  dir\\evil.txt  size=1\n", tmp)


def _manifest_dotted_component(tmp: Path) -> Report:
    return _manifest_report(f"{'a'*64}  dir/./evil.txt  size=1\n", tmp)


def _verify_missing_root(tmp: Path) -> Report:
    manifest = tmp / "MANIFEST.sha256"
    manifest.write_text("", encoding="utf-8")
    return verify_manifest(tmp / "missing", manifest)


def _tree_invalid_json(tmp: Path) -> Report:
    root = tmp / "tree_json"; root.mkdir()
    (root / "broken.json").write_text('{"x": ', encoding="utf-8")
    return audit_file_integrity(root)


def _tree_null_bytes(tmp: Path) -> Report:
    root = tmp / "tree_null"; root.mkdir()
    (root / "bad.txt").write_bytes(b"abc\x00def")
    return audit_file_integrity(root)


def _tree_invalid_utf8(tmp: Path) -> Report:
    root = tmp / "tree_utf8"; root.mkdir()
    (root / "bad.md").write_bytes(b"\xff\xfe")
    return audit_file_integrity(root)


def _tree_markdown_missing_link(tmp: Path) -> Report:
    root = tmp / "tree_md"; root.mkdir()
    (root / "README.md").write_text("[missing](docs/nope.md)\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_markdown_ref_missing_link(tmp: Path) -> Report:
    root = tmp / "tree_md_ref"; root.mkdir()
    (root / "README.md").write_text("[Guide][g]\n\n[g]: docs/nope.md\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_case_collision(tmp: Path) -> Report:
    root = tmp / "tree_case"; root.mkdir()
    (root / "Readme.md").write_text("a\n", encoding="utf-8")
    (root / "README.md").write_text("b\n", encoding="utf-8")
    return audit_file_integrity(root)


def _tree_bom(tmp: Path) -> Report:
    root = tmp / "tree_bom"; root.mkdir()
    (root / "config.json").write_bytes(b"\xef\xbb\xbf{}\n")
    return audit_file_integrity(root)


def _tree_cr_only(tmp: Path) -> Report:
    root = tmp / "tree_cr"; root.mkdir()
    (root / "README.md").write_bytes(b"a\rb\r")
    return audit_file_integrity(root)


def _tree_broken_symlink(tmp: Path) -> Report:
    root = tmp / "tree_link"; root.mkdir()
    link = root / "broken"
    try:
        link.symlink_to(root / "missing")
    except (OSError, NotImplementedError):
        report = Report(); report.record_skip("<symlink>", "symlinks unsupported") ; return report
    return audit_file_integrity(root)


def _tree_symlink_escape(tmp: Path) -> Report:
    root = tmp / "tree_link_escape"; root.mkdir()
    outside = tmp / "outside.txt"; outside.write_text("x", encoding="utf-8")
    link = root / "outside"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        report = Report(); report.record_skip("<symlink>", "symlinks unsupported") ; return report
    return audit_file_integrity(root)


def _zip_with_members(tmp: Path, members: list[tuple[str, bytes, int | None]]) -> Report:
    zp = tmp / "fixture.zip"
    with zipfile.ZipFile(zp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data, external_attr in members:
            info = zipfile.ZipInfo(name)
            if external_attr is not None:
                info.external_attr = external_attr
            zf.writestr(info, data)
    return audit_release(zp, run_cli_matrix=False)


def _zip_duplicate(tmp: Path) -> Report:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        return _zip_with_members(tmp, [("pkg/a.txt", b"1", None), ("pkg/a.txt", b"2", None)])


def _zip_traversal(tmp: Path) -> Report:
    return _zip_with_members(tmp, [("pkg/../evil.txt", b"x", None)])


def _zip_windows_drive(tmp: Path) -> Report:
    return _zip_with_members(tmp, [("C:/evil.txt", b"x", None)])


def _zip_backslash(tmp: Path) -> Report:
    return _zip_with_members(tmp, [("pkg\\evil.txt", b"x", None)])


def _zip_control_char(tmp: Path) -> Report:
    return _zip_with_members(tmp, [("pkg/bad\x01name.txt", b"x", None)])


def _zip_symlink(tmp: Path) -> Report:
    symlink_attr = (stat.S_IFLNK | 0o777) << 16
    return _zip_with_members(tmp, [("pkg/link", b"target", symlink_attr)])


def _zip_empty(tmp: Path) -> Report:
    zp = tmp / "empty.zip"
    with zipfile.ZipFile(zp, "w"):
        pass
    return audit_release(zp, run_cli_matrix=False)


def _zip_top_level_file(tmp: Path) -> Report:
    return _zip_with_members(tmp, [("README.md", b"x", None), ("pkg/a.txt", b"x", None)])


def _zip_high_compression(tmp: Path) -> Report:
    zp = tmp / "bombish.zip"
    with zipfile.ZipFile(zp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/huge.txt", b"0" * (11 * 1024 * 1024))
    return audit_release(zp, run_cli_matrix=False)


def _release_manifest_tamper(tmp: Path) -> Report:
    root = _minimal_project(tmp / "ai_code_filter_refactored_v30")
    (root / "README.md").write_text("tampered\n", encoding="utf-8")
    return audit_release(root, run_cli_matrix=False)


def _release_missing_manifest(tmp: Path) -> Report:
    root = _minimal_project(tmp / "ai_code_filter_refactored_v30_missing")
    (root / MANIFEST_NAME).unlink()
    return audit_release(root, run_cli_matrix=False)


def _release_bad_python(tmp: Path) -> Report:
    root = _minimal_project(tmp / "ai_code_filter_refactored_v30_badpy")
    (root / "ai_code_filter" / "bad.py").write_text("def broken(\n", encoding="utf-8")
    write_manifest(root)
    return audit_release(root, run_cli_matrix=False)


def _release_zip_valid(tmp: Path) -> Report:
    root = _minimal_project(tmp / "ai_code_filter_refactored_v30")
    return audit_release(_zip_tree(root, tmp / "valid.zip"), run_cli_matrix=False)


def adversarial_cases() -> list[AdversarialCase]:
    return [
        AdversarialCase("manifest_duplicate", "duplicate manifest entry", ("MANIFEST001",), _manifest_duplicate),
        AdversarialCase("manifest_negative_size", "negative manifest size", ("MANIFEST001",), _manifest_negative_size),
        AdversarialCase("manifest_non_integer_size", "non-integer manifest size", ("MANIFEST001",), _manifest_non_integer_size),
        AdversarialCase("manifest_absolute_path", "absolute manifest path", ("MANIFEST001",), _manifest_absolute_path),
        AdversarialCase("manifest_traversal", "traversal manifest path", ("MANIFEST001",), _manifest_traversal),
        AdversarialCase("manifest_backslash", "backslash manifest path", ("MANIFEST001",), _manifest_backslash),
        AdversarialCase("manifest_dotted_component", "dotted manifest path", ("MANIFEST001",), _manifest_dotted_component),
        AdversarialCase("verify_missing_root", "missing verify-manifest root", ("MANIFEST000",), _verify_missing_root),
        AdversarialCase("tree_invalid_json", "invalid JSON", ("STRUCT001",), _tree_invalid_json),
        AdversarialCase("tree_null_bytes", "NUL bytes", ("CORRUPT001",), _tree_null_bytes),
        AdversarialCase("tree_invalid_utf8", "invalid UTF-8", ("ENCODING001",), _tree_invalid_utf8),
        AdversarialCase("tree_markdown_missing_link", "missing Markdown link", ("LINK002",), _tree_markdown_missing_link),
        AdversarialCase("tree_markdown_ref_missing_link", "missing reference Markdown link", ("LINKREF002",), _tree_markdown_ref_missing_link),
        AdversarialCase("tree_case_collision", "case-insensitive path collision", ("PATH001",), _tree_case_collision),
        AdversarialCase("tree_bom", "UTF-8 BOM", ("ENCODING003",), _tree_bom),
        AdversarialCase("tree_cr_only", "CR-only line endings", ("LINES002",), _tree_cr_only),
        AdversarialCase("tree_broken_symlink", "broken symlink", ("PATH002",), _tree_broken_symlink),
        AdversarialCase("tree_symlink_escape", "symlink escapes root", ("PATH002",), _tree_symlink_escape),
        AdversarialCase("zip_duplicate", "duplicate zip member", ("ARCHIVE011",), _zip_duplicate),
        AdversarialCase("zip_traversal", "zip traversal path", ("ARCHIVE006",), _zip_traversal),
        AdversarialCase("zip_windows_drive", "Windows drive zip path", ("ARCHIVE006",), _zip_windows_drive),
        AdversarialCase("zip_backslash", "backslash zip path", ("ARCHIVE006",), _zip_backslash),
        AdversarialCase("zip_control_char", "control-char zip path", ("ARCHIVE006",), _zip_control_char),
        AdversarialCase("zip_symlink", "zip symlink entry", ("ARCHIVE007",), _zip_symlink),
        AdversarialCase("zip_empty", "empty zip", ("ARCHIVE005",), _zip_empty),
        AdversarialCase("zip_top_level_file", "top-level stray zip file", ("ARCHIVE008",), _zip_top_level_file),
        AdversarialCase("zip_high_compression", "suspicious zip compression ratio", ("ARCHIVE012", "ARCHIVE013"), _zip_high_compression),
        AdversarialCase("release_manifest_tamper", "tampered file with stale manifest", ("MANIFEST003", "MANIFEST004"), _release_manifest_tamper),
        AdversarialCase("release_missing_manifest", "missing release manifest", ("MANIFEST006",), _release_missing_manifest),
        AdversarialCase("release_bad_python", "broken Python file", ("PYCOMPILE001",), _release_bad_python),
    ]


def run_adversarial_suite() -> Report:
    report = Report()
    with TemporaryDirectory(prefix="acf-adversarial-") as tmp_s:
        base = Path(tmp_s)
        for case in adversarial_cases():
            case_dir = base / case.case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            try:
                observed = case.runner(case_dir)
            except Exception as exc:  # fixture runner failure is a suite defect, not target failure.
                report.add(Issue(file=f"<adversarial:{case.case_id}>", category="ADV002: Adversarial fixture crash", severity=Severity.HIGH, detector="adversarial_suite", description=f"Adversarial fixture crashed: {exc}", recommendation="Fix the adversarial fixture or underlying detector."))
                continue
            if observed.skipped_files:
                report.record_skip(f"<adversarial:{case.case_id}>", "; ".join(item.get("reason", "skipped") for item in observed.skipped_files))
                continue
            if not _has_expected(observed, case.expected_prefixes):
                report.add(_issue(case.case_id, case.title, case.expected_prefixes, _categories(observed)))
    return report


def adversarial_suite_summary() -> dict[str, object]:
    cases = adversarial_cases()
    return {
        "case_count": len(cases),
        "cases": [
            {"case_id": c.case_id, "title": c.title, "expected_prefixes": list(c.expected_prefixes)}
            for c in cases
        ],
    }
