from __future__ import annotations

import contextlib
import io
import json
import os
import py_compile
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unicodedata
import tomllib
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..artifacts import junit_xml, markdown_report, sarif_dict
from ..integrity import MANIFEST_NAME, audit_file_integrity, verify_manifest, _unsafe_path_reason
from ..coverage import coverage_matrix
from ..models import Issue, Report, Severity
from ..rules import build_default_catalog

_BAD_ARCHIVE_PARTS = ("__pycache__", ".pytest_cache", ".ai-code-filter", ".mypy_cache", ".pyright", ".ruff_cache", ".tox", ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "dist", "build", "htmlcov", ".coverage", ".nox", ".DS_Store", "Thumbs.db", "desktop.ini")
_BAD_SUFFIXES = (".pyc", ".pyo")
_VERSION_RE = re.compile(r"\bv?0\.\d+\.\d+\b|\bv0\.\d+\b|\bv\d+\b")


@dataclass(frozen=True)
class ReleaseAuditOptions:
    target: Path
    run_cli_matrix: bool = True
    fail_on_skipped_tools: bool = False


def _issue(rule: str, severity: Severity, description: str, recommendation: str, file: str = "<release>", location: str | None = None) -> Issue:
    return Issue(file=file, category=f"{rule}: Release integrity", severity=severity, detector="release_audit", description=description, recommendation=recommendation, location=location)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _parse_pyproject(root: Path) -> dict:
    path = root / "pyproject.toml"
    if not path.exists():
        return {}
    try:
        return tomllib.loads(_read_text(path))
    except tomllib.TOMLDecodeError:
        return {}


def _parse_pyproject_version(root: Path) -> str | None:
    return (_parse_pyproject(root).get("project", {}) or {}).get("version")


def _parse_init_version(root: Path) -> str | None:
    path = root / "ai_code_filter" / "__init__.py"
    if not path.exists():
        return None
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', _read_text(path))
    return match.group(1) if match else None


def _version_tokens(version: str | None) -> set[str]:
    if not version:
        return set()
    tokens = {version, f"v{version}"}
    parts = version.split(".")
    if len(parts) >= 2 and parts[0] == "0":
        tokens.add(f"v0.{parts[1]}")
        tokens.add(f"v{parts[1]}")
        tokens.add(f"0.{parts[1]}")
    return tokens

def _version_token(version: str | None) -> str | None:
    if not version:
        return None
    parts = version.split(".")
    if len(parts) >= 2 and parts[0] == "0":
        return f"v{parts[1]}"
    return "v" + version


def _is_historical_version_document(root: Path, path: Path, text: str) -> bool:
    """Return True when stale version tokens are explicitly historical evidence.

    Release documentation is allowed to contain old version tokens only when the
    document opts in with a visible marker. This keeps REL004 strict for current
    docs while avoiding false blockers for changelog/lineage artifacts.
    """
    rel = str(path.relative_to(root)).lower()
    if rel.startswith("docs/changelog"):
        return True
    head = text[:4096].lower()
    return "ai-code-filter-historical-versions" in head or '"historical_versions"' in head


def _stale_version_mentions(root: Path, current_version: str) -> list[tuple[Path, str]]:
    allowed = _version_tokens(current_version)
    stale: list[tuple[Path, str]] = []
    for pattern in ("README.md", "docs/**/*.md", "docs/**/*.json"):
        paths = [root / pattern] if "*" not in pattern else root.glob(pattern)
        for path in paths:
            if not path.exists() or not path.is_file():
                continue
            text = _read_text(path)
            if _is_historical_version_document(root, path, text):
                continue
            for match in _VERSION_RE.findall(text):
                if match not in allowed:
                    stale.append((path, match))
    return stale


def _audit_version_consistency(root: Path, report: Report, archive_root_name: str | None = None) -> None:
    pyproject_version = _parse_pyproject_version(root)
    init_version = _parse_init_version(root)
    if not pyproject_version:
        report.add(_issue("REL001", Severity.HIGH, "pyproject.toml does not expose a project version.", "Add [project].version and keep it in sync with ai_code_filter.__version__.", "pyproject.toml"))
        return
    if not init_version:
        report.add(_issue("REL002", Severity.HIGH, "ai_code_filter.__version__ is missing.", "Define __version__ and keep it in sync with pyproject.toml.", "ai_code_filter/__init__.py"))
    elif pyproject_version != init_version:
        report.add(_issue("REL003", Severity.HIGH, f"Version mismatch: pyproject={pyproject_version}, __version__={init_version}.", "Update pyproject.toml and ai_code_filter/__init__.py to the same version.", "ai_code_filter/__init__.py"))
    token = _version_token(pyproject_version)
    if archive_root_name and token and token not in archive_root_name:
        report.add(_issue("ARCHIVE001", Severity.HIGH, f"Archive root '{archive_root_name}' does not include expected token '{token}'.", "Name the archive root after the package release version.", archive_root_name))
    for path, stale in _stale_version_mentions(root, pyproject_version):
        rel = str(path.relative_to(root))
        report.add(_issue("REL004", Severity.MEDIUM, f"Documentation contains stale version mention '{stale}' while package version is {pyproject_version}.", "Update docs/README or mark the historical reference explicitly as changelog content.", rel, stale))


def _audit_pyproject_contract(root: Path, report: Report) -> None:
    path = root / "pyproject.toml"
    text = _read_text(path) if path.exists() else ""
    data = _parse_pyproject(root) if path.exists() else {}
    project = data.get("project", {}) or {}
    scripts = project.get("scripts", {}) or {}
    if scripts.get("ai-code-filter") != "ai_code_filter.cli:main":
        report.add(_issue("REL005", Severity.HIGH, "pyproject.toml does not declare the ai-code-filter console script correctly.", "Expose ai-code-filter = ai_code_filter.cli:main in [project.scripts].", "pyproject.toml"))
    deps = project.get("dependencies", []) or []
    mandatory_openai = any(str(dep).split("[", 1)[0].lower().replace("_", "-").startswith("openai") for dep in deps)
    if mandatory_openai:
        report.add(_issue("REL006", Severity.MEDIUM, "OpenAI dependency appears in mandatory project dependencies.", "Keep AI review dependencies optional so deterministic scans work offline.", "pyproject.toml"))
    if text and not data:
        report.add(_issue("REL007", Severity.HIGH, "pyproject.toml could not be parsed as TOML.", "Repair pyproject.toml before releasing.", "pyproject.toml"))

def _audit_hygiene(root: Path, report: Report) -> None:
    for path in root.rglob("*"):
        rel = str(path.relative_to(root))
        rel_parts = set(path.relative_to(root).parts)
        if any(part in rel_parts for part in _BAD_ARCHIVE_PARTS) or path.name.endswith(_BAD_SUFFIXES) or path.name.endswith(".egg-info"):
            report.add(_issue("HYGIENE001", Severity.HIGH, f"Runtime/cache/build artifact found in release archive: {rel}.", "Remove caches and generated package metadata from the release archive.", rel))


def _audit_embedded_manifest(root: Path, report: Report) -> None:
    manifest = root / MANIFEST_NAME
    if not manifest.exists():
        report.add(_issue("MANIFEST006", Severity.HIGH, "Release tree does not include MANIFEST.sha256.", "Generate and ship MANIFEST.sha256 for release integrity verification.", MANIFEST_NAME))
        return
    verification = verify_manifest(root, manifest)
    for issue in verification.issues:
        report.add(issue)
    for failed in verification.failed_files:
        report.record_failure(failed.file, failed.error)
    for skipped in verification.skipped_files:
        report.record_skip(skipped.file, skipped.reason)


def _audit_python_syntax(root: Path, report: Report) -> None:
    for path in root.rglob("*.py"):
        rel = str(path.relative_to(root))
        if any(part in _BAD_ARCHIVE_PARTS for part in path.relative_to(root).parts):
            continue
        try:
            with tempfile.NamedTemporaryFile(prefix="acf-pycompile-", suffix=".pyc") as tmp_pyc:
                py_compile.compile(str(path), cfile=tmp_pyc.name, doraise=True)
        except py_compile.PyCompileError as exc:
            report.add(_issue("PYCOMPILE001", Severity.CRITICAL, f"Python file does not compile: {exc.msg}", "Fix syntax/import-time compile errors before releasing.", rel))


def _audit_required_layout(root: Path, report: Report) -> None:
    required = ["ai_filter.py", "ai_code_filter", "tests", "README.md", "pyproject.toml"]
    for item in required:
        if not (root / item).exists():
            report.add(_issue("LAYOUT001", Severity.HIGH, f"Release is missing required path: {item}.", "Include the complete package, tests, README and pyproject in the release archive.", item))


def _audit_report_semantics(report: Report) -> None:
    sample = Report()
    sample.add(Issue(file="app.py", category="PY999: Sample", severity=Severity.HIGH, detector="sample", description="sample issue", recommendation="fix sample"))
    sample.record_failure("failed.py", RuntimeError("boom"))
    sample.record_skip("<pyright>", "pyright executable not found")
    summary = sample.summary()
    root = ET.fromstring(junit_xml(sample))
    tests = int(root.attrib.get("tests", "0"))
    failures = int(root.attrib.get("failures", "0"))
    errors = int(root.attrib.get("errors", "0"))
    skipped = int(root.attrib.get("skipped", "0"))
    if tests < failures + errors + skipped:
        report.add(_issue("REPORT001", Severity.HIGH, "JUnit tests count is lower than failures + errors + skipped.", "Ensure every issue, failed file, and skipped tool has a testcase entry."))
    if len(root.findall("testcase")) != tests:
        report.add(_issue("REPORT002", Severity.HIGH, "JUnit testcase count does not match tests attribute.", "Generate explicit testcase elements for issues, failures, skips, and green reports."))
    if skipped != summary["SKIPPED_FILES"] or not root.findall("testcase/skipped"):
        report.add(_issue("REPORT003", Severity.HIGH, "JUnit skipped metadata is incomplete.", "Represent each skipped file/tool as a skipped testcase."))
    sarif = sarif_dict(sample)
    notifications = sarif["runs"][0].get("invocations", [{}])[0].get("toolExecutionNotifications", [])
    if not any("failed.py" in note.get("message", {}).get("text", "") for note in notifications):
        report.add(_issue("REPORT004", Severity.MEDIUM, "SARIF lacks failed-file execution notification metadata.", "Add failed/skipped analysis notifications to SARIF invocations."))
    if not any("<pyright>" in note.get("message", {}).get("text", "") for note in notifications):
        report.add(_issue("REPORT005", Severity.MEDIUM, "SARIF lacks skipped-tool execution notification metadata.", "Add skipped analysis notifications to SARIF invocations."))
    md = markdown_report(sample)
    if "## Failed files" not in md or "## Skipped files" not in md:
        report.add(_issue("REPORT006", Severity.MEDIUM, "Markdown report hides failed/skipped analysis details.", "Print explicit failed/skipped sections in Markdown reports."))


def _audit_coverage_invariants(report: Report) -> None:
    matrix = coverage_matrix(build_default_catalog())
    total = int(matrix.get("total_capabilities", 0))
    if sum(matrix.get("by_language", {}).values()) != total:
        report.add(_issue("METRIC001", Severity.HIGH, "Coverage by_language does not sum to total_capabilities.", "Include analyzer capabilities in language totals or expose separate totals."))
    if sum(matrix.get("by_severity", {}).values()) != total:
        report.add(_issue("METRIC002", Severity.HIGH, "Coverage by_severity does not sum to total_capabilities.", "Include analyzer capabilities in severity totals or expose separate totals."))
    if total != len(matrix.get("rules", [])) + len(matrix.get("analyzer_capabilities", [])):
        report.add(_issue("METRIC003", Severity.HIGH, "Coverage total_capabilities is inconsistent with rules + analyzer_capabilities.", "Reconcile coverage totals with exported lists."))


def _run_cli(root: Path, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run a release-audit CLI probe without spawning a subprocess chain.

    The release gate validates command behavior and output-file contracts. Calling
    the CLI entrypoint in-process avoids sandbox-specific subprocess pipe hangs
    while still exercising the same parser and command handlers. ``timeout`` is
    kept for API compatibility with older callers.
    """
    from ..cli import main

    old_cwd = Path.cwd()
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        os.chdir(root)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = main(args)
            except SystemExit as exc:
                code = int(exc.code or 0) if isinstance(exc.code, int) else 1
    except Exception as exc:  # defensive: release audit must report probe failures, not crash.
        return subprocess.CompletedProcess([sys.executable, "ai_filter.py", *args], returncode=1, stdout=stdout.getvalue(), stderr=stderr.getvalue() + f"\n{type(exc).__name__}: {exc}")
    finally:
        os.chdir(old_cwd)
    return subprocess.CompletedProcess([sys.executable, "ai_filter.py", *args], returncode=int(code or 0), stdout=stdout.getvalue(), stderr=stderr.getvalue())

def _write_cli_matrix_release_fixture(path: Path, version: str = "0.30.0") -> Path:
    """Create a tiny valid release tree for nested release-audit smoke tests.

    The CLI matrix checks output-path behavior, not full project semantics. Using a
    tiny fixture prevents release-audit from recursively auditing the whole project
    while release-audit is already running.
    """
    token = _version_token(version) or "v0"
    fixture = path / f"mini_release_{token}"
    pkg = fixture / "ai_code_filter"
    tests = fixture / "tests"
    pkg.mkdir(parents=True, exist_ok=True)
    tests.mkdir(parents=True, exist_ok=True)
    (fixture / "ai_filter.py").write_text("from ai_code_filter.cli import main\nraise SystemExit(main())\n", encoding="utf-8")
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (tests / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
    (fixture / "README.md").write_text(f"# Mini Release {token}\n", encoding="utf-8")
    (fixture / "pyproject.toml").write_text(
        f'[project]\nname = "mini-release"\nversion = "{version}"\n[project.scripts]\nai-code-filter = "ai_code_filter.cli:main"\n',
        encoding="utf-8",
    )
    from ..integrity import write_manifest

    write_manifest(fixture)
    return fixture

def _audit_cli_behavior(root: Path, report: Report, fail_on_skipped_tools: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="acf-release-cli-") as tmp_s:
        tmp = Path(tmp_s)
        native_report = tmp / "input" / "report.json"
        native_report.parent.mkdir(parents=True, exist_ok=True)
        native_report.write_text(json.dumps({"issues": [], "failed_files": [], "skipped_files": [], "summary": {"TOTAL": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "FAILED_FILES": 0, "SKIPPED_FILES": 0}}, ensure_ascii=False), encoding="utf-8")
        tiny_code = tmp / "tiny.py"
        tiny_code.write_text("def ok():\n    return 1\n", encoding="utf-8")
        mini_release = _write_cli_matrix_release_fixture(tmp, _parse_pyproject_version(root) or "0.30.0")
        matrix = [
            # Heavy/self-checking commands first; lightweight report-format commands follow.
            # This keeps the release gate deterministic in constrained sandboxes while
            # preserving the same command coverage.
            ("analyze", ["analyze", str(tiny_code), "--no-ai", "--no-drift", "--output", str(tmp / "nested" / "analyze.json")], tmp / "nested" / "analyze.json"),
            ("benchmark", ["benchmark", "--output", str(tmp / "nested" / "benchmark.json")], tmp / "nested" / "benchmark.json"),
            ("release-audit", ["release-audit", str(mini_release), "--skip-cli-matrix", "--output", str(tmp / "nested" / "release.json")], tmp / "nested" / "release.json"),
            ("inspect-deps", ["inspect-deps", str(root), "--output", str(tmp / "nested" / "deps.json")], tmp / "nested" / "deps.json"),
            ("list-rules", ["list-rules", "--json", str(tmp / "nested" / "coverage.json")], tmp / "nested" / "coverage.json"),
            ("assistant-capabilities", ["assistant-capabilities", "--output", str(tmp / "nested" / "caps.json")], tmp / "nested" / "caps.json"),
            ("prompt-pack", ["prompt-pack", "--output", str(tmp / "nested" / "prompts.json")], tmp / "nested" / "prompts.json"),
            ("explain-report", ["explain-report", str(native_report), "--output", str(tmp / "nested" / "review.md")], tmp / "nested" / "review.md"),
            ("review-plan", ["review-plan", str(native_report), "--output", str(tmp / "nested" / "plan.json")], tmp / "nested" / "plan.json"),
            ("patch-plan", ["patch-plan", str(native_report), "--output", str(tmp / "nested" / "patch.json")], tmp / "nested" / "patch.json"),
        ]
        for name, args, expected in matrix:
            proc = _run_cli(root, args, timeout=8)
            if proc.returncode != 0:
                report.add(_issue("CLI001", Severity.HIGH, f"CLI command '{name}' failed with exit code {proc.returncode}.", "Fix CLI command behavior and add regression coverage.", name, (proc.stderr or proc.stdout)[-500:]))
            elif not expected.exists():
                report.add(_issue("CLI002", Severity.HIGH, f"CLI command '{name}' did not create nested output file.", "All --output commands must create missing parent directories.", name))
        type_out = tmp / "nested" / "typecheck.json"
        proc = _run_cli(root, ["type-check", str(tmp), "--ci", "--output", str(type_out)], timeout=8)
        data = {}
        if type_out.exists():
            try:
                data = json.loads(type_out.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                report.add(_issue("CISEM002", Severity.HIGH, "type-check --output produced invalid JSON.", "Always emit parseable native JSON reports.", "type-check", str(exc)))
        skipped = int(data.get("summary", {}).get("SKIPPED_FILES", len(data.get("skipped_files", []))) or 0) if data else 0
        if skipped and proc.returncode == 0:
            report.add(_issue("CISEM001", Severity.HIGH, "type-check --ci succeeded while required type-check tools were skipped.", "In CI mode, missing required verification tools must produce a non-zero exit code.", "type-check"))
        if fail_on_skipped_tools and skipped:
            report.add(_issue("CISEM003", Severity.MEDIUM, "Type-check tools were skipped in release audit environment.", "Install pyright/mypy or disable strict skipped-tool release policy explicitly.", "type-check"))


def _is_bad_zip_name(name: str) -> bool:
    if "//" in name:
        return True
    return _unsafe_path_reason(name) is not None


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def _audit_zip_crc(zf: zipfile.ZipFile, report: Report) -> None:
    try:
        bad_name = zf.testzip()
    except RuntimeError as exc:
        report.add(_issue("ARCHIVE009", Severity.CRITICAL, f"Zip CRC verification failed: {exc}.", "Rebuild the archive from a clean release tree."))
        return
    if bad_name:
        report.add(_issue("ARCHIVE010", Severity.CRITICAL, f"Zip member failed CRC check: {bad_name}.", "Rebuild the archive; the zip payload is corrupted.", bad_name))


def _audit_zip_members(zf: zipfile.ZipFile, report: Report) -> None:
    seen: set[str] = set()
    seen_casefold: dict[str, str] = {}
    seen_normcase: dict[str, str] = {}
    total_uncompressed = 0
    total_compressed = 0
    for info in zf.infolist():
        name = info.filename
        if not name:
            continue
        check_name = name.rstrip("/")
        if _is_bad_zip_name(check_name):
            report.add(_issue("ARCHIVE006", Severity.CRITICAL, f"Unsafe zip member path: {name}.", "Reject absolute paths, ambiguous names and traversal entries before extraction.", name))
        if _is_zip_symlink(info):
            report.add(_issue("ARCHIVE007", Severity.HIGH, f"Zip member is a symlink: {name}.", "Do not ship symlinks in portable release archives.", name))
        if name in seen:
            report.add(_issue("ARCHIVE011", Severity.HIGH, f"Duplicate zip member: {name}.", "Rebuild archives without duplicate filenames; unzip behavior may be ambiguous.", name))
        seen.add(name)
        cf = name.rstrip("/").casefold()
        if cf in seen_casefold and seen_casefold[cf] != name:
            report.add(_issue("ARCHIVE014", Severity.HIGH, f"Case-insensitive duplicate zip member: {name} conflicts with {seen_casefold[cf]}.", "Avoid archive entries that collide on case-insensitive filesystems.", name))
        seen_casefold[cf] = name
        ncf = unicodedata.normalize("NFKC", name.rstrip("/")).casefold()
        if ncf in seen_normcase and seen_normcase[ncf] != name:
            report.add(_issue("ARCHIVE015", Severity.HIGH, f"Unicode-normalized duplicate zip member: {name} conflicts with {seen_normcase[ncf]}.", "Avoid archive entries that collide after Unicode normalization.", name))
        seen_normcase[ncf] = name
        if name.endswith("/"):
            continue
        total_uncompressed += int(info.file_size)
        total_compressed += int(info.compress_size)
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000 and info.file_size > 10 * 1024 * 1024:
            report.add(_issue("ARCHIVE012", Severity.HIGH, f"Suspicious compression ratio for zip member: {name}.", "Review for zip-bomb style payloads before extraction.", name))
    if total_compressed and total_uncompressed / max(total_compressed, 1) > 500 and total_uncompressed > 50 * 1024 * 1024:
        report.add(_issue("ARCHIVE013", Severity.HIGH, "Suspicious overall zip compression ratio.", "Review archive contents for zip-bomb style payloads before release.", "<archive>"))


def _safe_extract(zf: zipfile.ZipFile, destination: Path, report: Report) -> None:
    for info in zf.infolist():
        name = info.filename
        if not name or name.endswith("/"):
            continue
        if _is_bad_zip_name(name.rstrip("/")) or _is_zip_symlink(info):
            continue
        if name.endswith("/"):
            continue
        zf.extract(info, destination)


def _copy_or_extract(target: Path) -> tuple[tempfile.TemporaryDirectory[str] | None, Path, str | None, Report]:
    report = Report()
    if target.is_file() and target.suffix == ".zip":
        tmp = tempfile.TemporaryDirectory(prefix="acf-release-zip-")
        try:
            with zipfile.ZipFile(target) as zf:
                _audit_zip_crc(zf, report)
                _audit_zip_members(zf, report)
                names = [n for n in zf.namelist() if n and not n.endswith("/")]
                if not names:
                    report.add(_issue("ARCHIVE005", Severity.CRITICAL, "Archive is empty.", "Rebuild the release archive with one versioned project root.", str(target)))
                    return tmp, Path(tmp.name), None, report
                top_level_files = [n for n in names if "/" not in n]
                roots = {n.split("/", 1)[0] for n in names if "/" in n and not _is_bad_zip_name(n)}
                if top_level_files:
                    report.add(_issue("ARCHIVE008", Severity.HIGH, f"Archive contains top-level files outside the versioned root: {top_level_files[:5]}.", "Package every release file under exactly one root directory.", str(target)))
                if len(roots) != 1:
                    report.add(_issue("ARCHIVE002", Severity.HIGH, f"Archive must contain exactly one root directory, found {sorted(roots)}.", "Package releases under one versioned root directory.", str(target)))
                _safe_extract(zf, Path(tmp.name), report)
            root_name = next(iter(roots)) if len(roots) == 1 else None
            root = Path(tmp.name) / root_name if root_name else Path(tmp.name)
            return tmp, root, root_name, report
        except zipfile.BadZipFile as exc:
            report.add(_issue("ARCHIVE003", Severity.CRITICAL, f"Invalid zip archive: {exc}.", "Rebuild the release archive.", str(target)))
            return tmp, Path(tmp.name), None, report
    return None, target.resolve(), None, report


def audit_release(target: str | Path, run_cli_matrix: bool = True, fail_on_skipped_tools: bool = False) -> Report:
    tmp, root, archive_root_name, report = _copy_or_extract(Path(target))
    try:
        if not root.exists():
            report.add(_issue("ARCHIVE004", Severity.CRITICAL, f"Release target does not exist: {root}.", "Pass an existing project directory or zip archive."))
            return report
        _audit_required_layout(root, report)
        _audit_version_consistency(root, report, archive_root_name=archive_root_name or root.name)
        _audit_pyproject_contract(root, report)
        _audit_hygiene(root, report)
        _audit_embedded_manifest(root, report)
        _audit_python_syntax(root, report)
        integrity_report = audit_file_integrity(root)
        report.extend(integrity_report.issues)
        for failed in integrity_report.failed_files:
            report.record_failure(failed.file, failed.error)
        for skipped in integrity_report.skipped_files:
            report.record_skip(skipped.file, skipped.reason)
        _audit_report_semantics(report)
        _audit_coverage_invariants(report)
        if run_cli_matrix:
            ai_filter = root / "ai_filter.py"
            if not ai_filter.exists():
                report.add(_issue("CLI000", Severity.HIGH, "Release target lacks ai_filter.py CLI entrypoint.", "Include the thin CLI entrypoint in the release archive.", str(ai_filter)))
            else:
                _audit_cli_behavior(root, report, fail_on_skipped_tools=fail_on_skipped_tools)
        return report
    finally:
        if tmp is not None:
            tmp.cleanup()
