from __future__ import annotations

import hashlib
import configparser
import json
import os
import re
import stat
import unicodedata
import posixpath
from urllib.parse import unquote
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Issue, Report, Severity

MANIFEST_NAME = "MANIFEST.sha256"
_TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".toml", ".xml", ".yaml", ".yml",
    ".html", ".css", ".js", ".ts", ".tsx", ".jsx", ".rst", ".ini", ".cfg",
}
_STRUCTURED_SUFFIXES = {".json", ".toml", ".xml"}
_BAD_PARTS = {"__pycache__", ".pytest_cache", ".ai-code-filter", ".mypy_cache", ".pyright", ".ruff_cache", ".tox", ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "dist", "build", "htmlcov", ".coverage", ".nox", ".DS_Store", "Thumbs.db", "desktop.ini", "__MACOSX", ".idea", ".vscode", ".env", ".env.local", ".env.production", ".env.development", ".env.test"}
_BINARY_SIGNATURES = (b"\x7fELF", b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"%PDF")

_CONTROL_PATH_RE = re.compile(r"[\x00-\x1f\x7f]")
_RESERVED_WINDOWS_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
_MAX_PATH_LEN = 240
_MAX_PART_LEN = 120
_UNSAFE_SEPARATOR_CHARS = {"\u2044", "\u2215", "\uff0f", "\u29f8", "\u2571", "\u1735", "\u1736"}
_UNSAFE_DOT_CHARS = {"\uff0e", "\u2024", "\u2027", "\u2219", "\u00b7"}
_UNSAFE_COLON_CHARS = {"\uff1a", "\ua789", "\u2236", "\u02d0", "\u02f8"}
_SUPERSCRIPT_DIGITS = str.maketrans({"¹": "1", "²": "2", "³": "3", "⁴": "4", "⁵": "5", "⁶": "6", "⁷": "7", "⁸": "8", "⁹": "9"})


def _has_unicode_format_controls(value: str) -> bool:
    return any(unicodedata.category(ch) == "Cf" for ch in value)


def _has_nonportable_unicode_controls(value: str) -> bool:
    # Cc is handled by _CONTROL_PATH_RE, but keep the full C* family out of
    # release paths: surrogate/private/unassigned/noncharacters are ambiguous
    # across zip tools, filesystems and terminals.
    return any(unicodedata.category(ch) in {"Cs", "Co", "Cn"} for ch in value)


def _decode_for_path_check(value: str) -> str:
    try:
        return unquote(value)
    except Exception:
        return value


def _has_percent_encoded_separator(value: str, max_depth: int = 8) -> bool:
    """Return True when percent-decoding reveals separators inside a component.

    A path like ``pkg/docs%2Fguide.md`` already contains a real slash between
    components; the dangerous ambiguity is that a *single raw component* decodes
    into multiple components. Repeated decoding catches double-encoded payloads
    such as ``%252F``.
    """
    for raw_component in value.replace("\\", "/").split("/"):
        current = raw_component
        for _ in range(max_depth):
            decoded = _decode_for_path_check(current)
            if decoded == current:
                break
            if "/" in decoded or "\\" in decoded:
                return True
            current = decoded
    return False


def _normalized_collision_key(rel: str) -> str:
    return unicodedata.normalize("NFKC", _decode_for_path_check(rel)).casefold()


def _normalized_device_stem(part: str) -> str:
    stem = part.rstrip(" .").split(".", 1)[0].upper()
    return stem.translate(_SUPERSCRIPT_DIGITS)


def _unsafe_path_reason(rel: str) -> str | None:
    if _has_percent_encoded_separator(rel):
        return "percent-encoded path separator"
    decoded = _decode_for_path_check(rel)
    if rel != decoded and decoded != rel:
        # Re-check decoded payload to catch percent-encoded traversal/backslashes/drive paths.
        nested = _unsafe_path_reason(decoded)
        if nested:
            return f"percent-encoded unsafe path ({nested})"
    if not rel:
        return "empty path"
    if rel != rel.strip():
        return "leading/trailing whitespace"
    if "  " in rel:
        return "ambiguous double-space manifest delimiter"
    if len(rel) > _MAX_PATH_LEN:
        return "path too long"
    if rel.startswith("~"):
        return "home-directory shorthand path"
    if rel.startswith(("/", "\\")) or "\\" in rel:
        return "absolute or backslash path"
    if any(ch in rel for ch in _UNSAFE_SEPARATOR_CHARS):
        return "unicode slash-like separator in path"
    if any(ch in rel for ch in _UNSAFE_DOT_CHARS):
        return "unicode dot-like separator in path"
    if any(ch in rel for ch in _UNSAFE_COLON_CHARS):
        return "unicode colon-like separator in path"
    if _CONTROL_PATH_RE.search(rel) or _has_unicode_format_controls(rel):
        return "control/format character in path"
    if _has_nonportable_unicode_controls(rel):
        return "nonportable Unicode control/private/unassigned character in path"
    if ":" in rel:
        return "colon/drive/ADS path component"
    parts = rel.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return "empty/dotted/traversal component"
    for part in parts:
        if part != part.strip():
            return "leading/trailing whitespace path component"
        if part.startswith("~"):
            return "home-directory shorthand path component"
        nfkc_part = unicodedata.normalize("NFKC", part)
        if nfkc_part in {".", ".."}:
            return "unicode-normalized dotted/traversal component"
        if any(sep in nfkc_part for sep in ("/", "\\")):
            return "unicode-normalized path separator"
        if ":" in nfkc_part:
            return "unicode-normalized colon/drive/ADS path component"
        stem = _normalized_device_stem(nfkc_part)
        if stem in _RESERVED_WINDOWS_NAMES:
            return "reserved Windows device name"
        if part.endswith((" ", ".")) or nfkc_part.endswith((" ", ".")):
            return "trailing space/dot component"
        if len(part) > _MAX_PART_LEN:
            return "path component too long"
    return None


def _is_unsafe_manifest_path(rel: str) -> bool:
    return _unsafe_path_reason(rel) is not None



@dataclass(frozen=True)
class ManifestEntry:
    path: str
    sha256: str
    size: int


def _is_ignored(path: Path, root: Path, extra_ignored: set[str] | None = None) -> bool:
    rel = path.relative_to(root)
    ignored = set(_BAD_PARTS)
    if extra_ignored:
        ignored.update(extra_ignored)
    return any(part in ignored for part in rel.parts) or path.name == MANIFEST_NAME


def _iter_files(root: Path, extra_ignored: set[str] | None = None) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_file() and not _is_ignored(path, root, extra_ignored):
            yield path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def generate_manifest(root: str | Path, extra_ignored: set[str] | None = None) -> list[ManifestEntry]:
    """Generate manifest entries for a release tree.

    Raises:
        ValueError: if the root does not exist or is not a directory.
        OSError: if a file cannot be read while hashing.
    """
    base = Path(root).resolve()
    if not base.exists() or not base.is_dir():
        raise ValueError(f"Manifest root does not exist or is not a directory: {root}")
    entries: list[ManifestEntry] = []
    seen_raw: set[str] = set()
    seen_collision: dict[str, str] = {}
    for path in _iter_files(base, extra_ignored):
        rel = str(path.relative_to(base)).replace(os.sep, "/")
        reason = _unsafe_path_reason(rel)
        if reason:
            raise ValueError(f"Cannot generate manifest for unsafe path: {rel} ({reason})")
        if rel in seen_raw:
            raise ValueError(f"Duplicate manifest path while generating manifest: {rel}")
        seen_raw.add(rel)
        collision_key = _normalized_collision_key(rel)
        if collision_key in seen_collision and seen_collision[collision_key] != rel:
            raise ValueError(f"Manifest path collision: {rel} conflicts with {seen_collision[collision_key]}")
        seen_collision[collision_key] = rel
        entries.append(ManifestEntry(rel, sha256_file(path), path.stat().st_size))
    return entries


def manifest_text(entries: Iterable[ManifestEntry]) -> str:
    lines = [f"{entry.sha256}  {entry.path}  size={entry.size}" for entry in sorted(entries, key=lambda item: item.path)]
    return "\n".join(lines) + ("\n" if lines else "")


def write_manifest(root: str | Path, output: str | Path | None = None) -> Path:
    base = Path(root).resolve()
    out = Path(output) if output is not None else base / MANIFEST_NAME
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(manifest_text(generate_manifest(base)), encoding="utf-8")
    return out


def parse_manifest(path: str | Path) -> list[ManifestEntry]:
    """Parse a SHA256 manifest.

    Raises:
        OSError: if the manifest cannot be read.
        ValueError: if a manifest line is malformed or unsafe.
    """
    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    seen_collision: dict[str, str] = {}
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split("  ")
        if len(parts) != 3 or not parts[2].startswith("size="):
            raise ValueError(f"Invalid manifest line {line_no}: {line}")
        digest, rel, size_s = parts[0], parts[1], parts[2][5:]
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise ValueError(f"Invalid sha256 digest on line {line_no}: {digest}")
        reason = _unsafe_path_reason(rel)
        if reason:
            raise ValueError(f"Unsafe manifest path on line {line_no}: {rel} ({reason})")
        if rel in seen:
            raise ValueError(f"Duplicate manifest entry on line {line_no}: {rel}")
        seen.add(rel)
        collision_key = _normalized_collision_key(rel)
        if collision_key in seen_collision and seen_collision[collision_key] != rel:
            raise ValueError(f"Manifest path collision on line {line_no}: {rel} conflicts with {seen_collision[collision_key]}")
        seen_collision[collision_key] = rel
        if size_s != size_s.strip():
            raise ValueError(f"Invalid file size on line {line_no}: {size_s}")
        try:
            size = int(size_s)
        except ValueError as exc:
            raise ValueError(f"Invalid file size on line {line_no}: {size_s}") from exc
        if size < 0:
            raise ValueError(f"Negative file size on line {line_no}: {size}")
        entries.append(ManifestEntry(rel, digest.lower(), size))
    return entries

def _integrity_issue(rule: str, severity: Severity, file: str, description: str, recommendation: str, location: str | None = None) -> Issue:
    return Issue(file=file, category=f"{rule}: Artifact integrity", severity=severity, detector="integrity", description=description, recommendation=recommendation, location=location)


def verify_manifest(root: str | Path, manifest_path: str | Path) -> Report:
    base = Path(root).resolve()
    report = Report()
    if not base.exists() or not base.is_dir():
        report.add(_integrity_issue("MANIFEST000", Severity.CRITICAL, str(root), "Manifest root does not exist or is not a directory.", "Pass an existing extracted release directory."))
        return report
    try:
        entries = parse_manifest(manifest_path)
    except (OSError, ValueError) as exc:
        report.add(_integrity_issue("MANIFEST001", Severity.CRITICAL, str(manifest_path), f"Manifest cannot be parsed: {exc}", "Regenerate the manifest from a clean release tree."))
        return report
    expected = {entry.path: entry for entry in entries}
    actual_paths = {str(path.relative_to(base)).replace(os.sep, "/"): path for path in _iter_files(base)}
    for rel, entry in expected.items():
        path = actual_paths.get(rel)
        direct_path = base / rel
        if direct_path.is_symlink():
            report.add(_integrity_issue("MANIFEST006", Severity.CRITICAL, rel, "Manifest entry resolves to a symlink in the release tree.", "Replace symlinks with regular files before generating/verifying manifests."))
            continue
        if path is None:
            report.add(_integrity_issue("MANIFEST002", Severity.CRITICAL, rel, "Manifest entry is missing from the release tree.", "Restore the file or regenerate the manifest intentionally."))
            continue
        actual_size = path.stat().st_size
        if actual_size != entry.size:
            report.add(_integrity_issue("MANIFEST003", Severity.CRITICAL, rel, f"File size changed: manifest={entry.size}, actual={actual_size}.", "Rebuild the artifact or regenerate the manifest after review."))
        actual_digest = sha256_file(path)
        if actual_digest != entry.sha256:
            report.add(_integrity_issue("MANIFEST004", Severity.CRITICAL, rel, "File SHA256 does not match the manifest.", "Treat this as corruption or unauthorized modification."))
    for rel in sorted(set(actual_paths) - set(expected)):
        if rel == MANIFEST_NAME:
            continue
        report.add(_integrity_issue("MANIFEST005", Severity.HIGH, rel, "File is present but absent from the manifest.", "Regenerate the manifest or remove the stray file."))
    return report


def _looks_text(path: Path) -> bool:
    return path.suffix.lower() in _TEXT_SUFFIXES or path.name in {"README", "LICENSE", MANIFEST_NAME}


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _decode_text(path: Path, data: bytes, report: Report, rel: str) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        report.add(_integrity_issue("ENCODING001", Severity.HIGH, rel, f"Text file is not valid UTF-8: {exc}.", "Store release text files as valid UTF-8."))
        return None


def _audit_text_file(path: Path, rel: str, report: Report) -> None:
    data = _read_bytes(path)
    if data.startswith(b"\xef\xbb\xbf") and path.suffix.lower() in {".py", ".json", ".toml", ".xml", ".yaml", ".yml"}:
        report.add(_integrity_issue("ENCODING003", Severity.MEDIUM, rel, "Text file starts with a UTF-8 BOM.", "Remove BOM markers from source/config files for deterministic tooling."))
    if b"\x00" in data:
        report.add(_integrity_issue("CORRUPT001", Severity.HIGH, rel, "Text-like file contains NUL bytes.", "Recreate the file from source; NUL bytes usually indicate binary corruption or truncation."))
    if any(data.startswith(sig) for sig in _BINARY_SIGNATURES) and _looks_text(path):
        report.add(_integrity_issue("CORRUPT002", Severity.HIGH, rel, "Text extension appears to contain binary data.", "Fix the file extension or remove the binary payload from the source tree."))
    text = _decode_text(path, data, report, rel)
    if text is None:
        return
    if "\r\n" in text and "\n" in text.replace("\r\n", ""):
        report.add(_integrity_issue("LINES001", Severity.MEDIUM, rel, "File uses mixed CRLF and LF line endings.", "Normalize line endings before release."))
    if "\r" in text.replace("\r\n", ""):
        report.add(_integrity_issue("LINES002", Severity.MEDIUM, rel, "File uses legacy CR-only line endings.", "Normalize line endings before release."))
    if text and not text.endswith("\n") and path.suffix.lower() in {".py", ".md", ".rst", ".txt", ".json", ".toml", ".xml", ".yaml", ".yml"}:
        report.add(_integrity_issue("TRUNC001", Severity.LOW, rel, "Text file does not end with a newline.", "Ensure generated/source text files are fully written and normalized."))
    if "\ufffd" in text:
        report.add(_integrity_issue("ENCODING002", Severity.MEDIUM, rel, "Text contains Unicode replacement characters.", "Check for mojibake or lossy decoding before release."))
    _audit_structured_text(path, rel, text, report)


def _reject_duplicate_json_keys(pairs):
    seen = set()
    out = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"Duplicate JSON key: {key}")
        seen.add(key)
        out[key] = value
    return out


def _reject_json_constant(value: str):
    raise ValueError(f"Non-standard JSON constant: {value}")


def _audit_structured_text(path: Path, rel: str, text: str, report: Report) -> None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            json.loads(text, object_pairs_hook=_reject_duplicate_json_keys, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            report.add(_integrity_issue("STRUCT001", Severity.HIGH, rel, f"Invalid JSON: {exc}.", "Regenerate or repair the JSON file before release."))
    elif suffix == ".toml":
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            report.add(_integrity_issue("STRUCT002", Severity.HIGH, rel, f"Invalid TOML: {exc}.", "Repair TOML metadata before release."))
    elif suffix == ".xml":
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            report.add(_integrity_issue("STRUCT006", Severity.HIGH, rel, "XML contains DOCTYPE/ENTITY declarations.", "Remove DTD/entity declarations from release XML artifacts."))
            return
        try:
            ET.fromstring(text)
        except ET.ParseError as exc:
            report.add(_integrity_issue("STRUCT003", Severity.HIGH, rel, f"Invalid XML: {exc}.", "Repair XML report/metadata before release."))
    elif suffix in {".yaml", ".yml"}:
        _audit_yaml_like(rel, text, report)
    elif suffix in {".ini", ".cfg"}:
        _audit_ini_like(rel, text, report)


def _audit_yaml_like(rel: str, text: str, report: Report) -> None:
    seen_by_context: dict[tuple[int, tuple[tuple[int, int], ...]], set[str]] = {}
    list_counters: dict[int, int] = {}
    for line_no, line in enumerate(text.splitlines(), start=1):
        if line.startswith("\t"):
            report.add(_integrity_issue("STRUCT004", Severity.MEDIUM, rel, "YAML-like file contains tab indentation.", "Use spaces for YAML indentation.", f"line {line_no}"))
            return
        if line.count("[") != line.count("]") or line.count("{") != line.count("}"):
            report.add(_integrity_issue("STRUCT005", Severity.MEDIUM, rel, "YAML-like file has unbalanced inline collection brackets.", "Validate YAML with a parser before release.", f"line {line_no}"))
            return
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "{" in stripped and "}" in stripped:
            inline = stripped[stripped.find("{") + 1:stripped.rfind("}")]
            inline_seen: set[str] = set()
            for chunk in inline.split(","):
                if ":" not in chunk:
                    continue
                inline_key = chunk.split(":", 1)[0].strip().strip("'\"")
                if inline_key in inline_seen:
                    report.add(_integrity_issue("STRUCT009", Severity.MEDIUM, rel, f"YAML-like inline map contains a duplicate key: {inline_key}.", "Remove duplicate YAML inline-map keys or validate with a strict YAML parser.", f"line {line_no}"))
                    return
                inline_seen.add(inline_key)
        indent = len(line) - len(line.lstrip(" "))
        is_list_item_key = stripped.startswith("- ")
        if is_list_item_key:
            list_counters[indent] = list_counters.get(indent, 0) + 1
            # A new list item starts a fresh mapping scope for this item and deeper keys.
            for known_indent in list(list_counters):
                if known_indent > indent:
                    del list_counters[known_indent]
        if ":" not in stripped:
            continue
        key = stripped.split(":", 1)[0].strip()
        if key.startswith("-"):
            key = key[1:].strip()
        if not key or " " in key:
            continue
        max_context_indent = indent if is_list_item_key else indent - 1
        context = (indent, tuple(sorted((i, c) for i, c in list_counters.items() if i <= max_context_indent)))
        bucket = seen_by_context.setdefault(context, set())
        if key in bucket:
            report.add(_integrity_issue("STRUCT007", Severity.MEDIUM, rel, f"YAML-like file contains a duplicate key: {key}.", "Remove duplicate YAML keys or validate with a strict YAML parser.", f"line {line_no}"))
            return
        bucket.add(key)


def _audit_ini_like(rel: str, text: str, report: Report) -> None:
    parser = configparser.ConfigParser(strict=True)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        report.add(_integrity_issue("STRUCT008", Severity.MEDIUM, rel, f"Invalid INI/CFG file: {exc}.", "Repair duplicate sections/options or malformed INI syntax before release."))


def _split_markdown_target(raw: str) -> str:
    target = raw.strip().strip("<>")
    if not target:
        return ""
    if target.startswith("<") and ">" in target:
        return target[1:target.index(">")].strip()
    quote_positions = [idx for idx in (target.find(' "'), target.find(" \'")) if idx >= 0]
    if quote_positions:
        target = target[:min(quote_positions)].strip()
    return target


def _audit_one_markdown_target(root: Path, path: Path, rel: str, target: str, report: Report, rule_prefix: str = "LINK") -> None:
    target = _split_markdown_target(target)
    if not target or "://" in target or target.startswith("#") or target.startswith("mailto:"):
        return
    raw_target_path = target.split("#", 1)[0]
    target_path = _decode_for_path_check(raw_target_path)
    if not target_path:
        return
    unsafe_reason = _unsafe_path_reason(raw_target_path)
    if unsafe_reason:
        report.add(_integrity_issue(f"{rule_prefix}001", Severity.MEDIUM, rel, f"Markdown link uses an unsafe path: {target} ({unsafe_reason}).", "Use relative POSIX-style paths inside the release archive."))
        return
    candidate = (path.parent / target_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        report.add(_integrity_issue(f"{rule_prefix}001", Severity.MEDIUM, rel, f"Markdown link escapes the release root: {target}.", "Keep documentation links inside the release archive or use explicit external URLs."))
        return
    if not candidate.exists():
        report.add(_integrity_issue(f"{rule_prefix}002", Severity.MEDIUM, rel, f"Markdown link target is missing: {target}.", "Fix or remove broken internal documentation links."))


def _audit_markdown_links(root: Path, path: Path, rel: str, text: str, report: Report) -> None:
    for match in re.finditer(r"!?\[[^\]]+\]\(([^)]+)\)", text):
        _audit_one_markdown_target(root, path, rel, match.group(1), report, "LINK")
    for match in re.finditer(r"^\s*\[[^\]]+\]:\s+(.+?)\s*$", text, re.MULTILINE):
        _audit_one_markdown_target(root, path, rel, match.group(1), report, "LINKREF")
    for match in re.finditer(r"\b(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", text, re.IGNORECASE):
        _audit_one_markdown_target(root, path, rel, match.group(1), report, "LINKHTML")
    for match in re.finditer(r"\b(?:href|src)\s*=\s*([^\s>\"']+)", text, re.IGNORECASE):
        _audit_one_markdown_target(root, path, rel, match.group(1), report, "LINKHTML")

def audit_file_integrity(root: str | Path) -> Report:
    base = Path(root).resolve()
    report = Report()
    if not base.exists() or not base.is_dir():
        report.add(_integrity_issue("ROOT001", Severity.CRITICAL, str(root), "Integrity root does not exist or is not a directory.", "Pass an existing release tree."))
        return report
    reported_bad_parts: set[str] = set()
    for raw in sorted(base.rglob("*")):
        rel_raw = str(raw.relative_to(base)).replace(os.sep, "/")
        bad_parts = [part for part in raw.relative_to(base).parts if part in _BAD_PARTS]
        if bad_parts:
            bad_key = "/".join(raw.relative_to(base).parts[: raw.relative_to(base).parts.index(bad_parts[0]) + 1])
            if bad_key not in reported_bad_parts:
                reported_bad_parts.add(bad_key)
                report.add(_integrity_issue("HYGIENE002", Severity.HIGH, bad_key, "Repository/cache/dependency/build directory found in release tree.", "Remove VCS, virtualenv, dependency, cache and build-output directories from release artifacts."))
            continue
        unsafe_reason = _unsafe_path_reason(rel_raw)
        if unsafe_reason:
            report.add(_integrity_issue("PATH003", Severity.HIGH, rel_raw, f"Release tree path is unsafe: {unsafe_reason}.", "Rename files to portable, unambiguous POSIX-style relative paths."))
        if raw.is_symlink():
            try:
                target = raw.resolve(strict=True)
                try:
                    target.relative_to(base)
                    description = "Symlink found inside release tree."
                except ValueError:
                    description = "Symlink points outside release tree."
            except (OSError, RuntimeError):
                description = "Broken or cyclic symlink found inside release tree."
            report.add(_integrity_issue("PATH002", Severity.HIGH, rel_raw, description, "Replace symlinks with regular files in portable release artifacts."))
    seen_casefold: dict[str, str] = {}
    seen_normcase: dict[str, str] = {}
    for candidate_path in sorted(base.rglob("*")):
        if any(part in _BAD_PARTS for part in candidate_path.relative_to(base).parts):
            continue
        rel_candidate = str(candidate_path.relative_to(base)).replace(os.sep, "/")
        lowered_candidate = rel_candidate.casefold()
        if lowered_candidate in seen_casefold and seen_casefold[lowered_candidate] != rel_candidate:
            report.add(_integrity_issue("PATH001", Severity.HIGH, rel_candidate, f"Case-insensitive path collision with {seen_casefold[lowered_candidate]}.", "Rename files/directories to avoid collisions on macOS/Windows filesystems."))
        seen_casefold[lowered_candidate] = rel_candidate
        normalized_candidate = unicodedata.normalize("NFKC", rel_candidate).casefold()
        if normalized_candidate in seen_normcase and seen_normcase[normalized_candidate] != rel_candidate:
            report.add(_integrity_issue("PATH004", Severity.HIGH, rel_candidate, f"Unicode-normalized path collision with {seen_normcase[normalized_candidate]}.", "Normalize filenames and avoid visually equivalent Unicode path collisions."))
        seen_normcase[normalized_candidate] = rel_candidate
    for path in _iter_files(base):
        rel = str(path.relative_to(base)).replace(os.sep, "/")
        if path.stat().st_size == 0 and rel in {"README.md", "pyproject.toml", "ai_filter.py", "ai_code_filter/__init__.py"}:
            report.add(_integrity_issue("EMPTY001", Severity.HIGH, rel, "Critical release file is empty.", "Restore required metadata/source content before release."))
        mode = path.stat().st_mode
        if path.suffix == ".py" and (mode & stat.S_IXUSR) and path.name != "ai_filter.py":
            report.add(_integrity_issue("PERM001", Severity.LOW, rel, "Python module has executable permission unexpectedly.", "Remove executable bits from library modules unless explicitly required."))
        if _looks_text(path):
            _audit_text_file(path, rel, report)
            if path.suffix.lower() == ".md":
                text = path.read_text(encoding="utf-8", errors="replace")
                _audit_markdown_links(base, path, rel, text, report)
    return report
