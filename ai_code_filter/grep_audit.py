from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import DEFAULT_IGNORED_DIRS, BINARY_EXTENSIONS
from .finding_core import FindingCore
from .models import Issue, Report, Severity

_TEXT_EXTENSIONS = {
    ".py", ".pyi", ".js", ".ts", ".jsx", ".tsx", ".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".env", ".example",
    ".md", ".rst", ".txt", ".sh", ".bash", ".zsh", ".ps1", ".sql", ".html", ".css", ".xml", ".service", ".conf",
}

_DEFAULT_EXCLUDES = {
    ".git/**", "__pycache__/**", ".pytest_cache/**", ".mypy_cache/**", ".ruff_cache/**", ".venv/**", "venv/**", "node_modules/**",
    "dist/**", "build/**", ".ai-code-filter/**", "MANIFEST.sha256",
}

_BUILTIN_PATTERNS: tuple[dict[str, Any], ...] = (
    {
        "id": "grep.merge_conflict_marker",
        "regex": r"^(<<<<<<<|=======|>>>>>>>)\s",
        "severity": "HIGH",
        "description": "Unresolved merge-conflict marker found in a text file.",
        "recommendation": "Resolve the merge conflict before release; conflict markers must never ship.",
        "confidence": "high",
    },
    {
        "id": "grep.private_key_material",
        "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Private key material appears to be committed into the project tree.",
        "recommendation": "Remove the key, rotate it, and keep secrets outside source control.",
        "confidence": "high",
    },
)


@dataclass(frozen=True)
class GrepPattern:
    id: str
    regex: str
    severity: Severity = Severity.MEDIUM
    description: str = "Pattern matched."
    recommendation: str = "Review the matched pattern and either fix it or add a narrow documented exclusion."
    confidence: str = "medium"
    include: tuple[str, ...] = ("**/*",)
    exclude: tuple[str, ...] = ()
    flags: int = 0


@dataclass(frozen=True)
class GrepAuditSummary:
    scanned_files: int
    patterns: int
    matches: int
    skipped_files: int

    def to_dict(self) -> dict[str, int]:
        return {
            "scanned_files": self.scanned_files,
            "patterns": self.patterns,
            "matches": self.matches,
            "skipped_files": self.skipped_files,
        }


def audit_grep_patterns(
    project: str | Path,
    *,
    pattern_file: str | Path | None = None,
    inline_patterns: Iterable[str] = (),
    include_builtins: bool = True,
    include: Iterable[str] = (),
    exclude: Iterable[str] = (),
    max_matches: int = 500,
) -> tuple[Report, GrepAuditSummary]:
    """Run high-confidence grep/pattern checks across text files.

    This gate is intentionally deterministic and evidence-oriented. It is not a
    replacement for Semgrep or AST rules; it catches repo-wide literal and regex
    hazards such as conflict markers, private keys, forbidden terms, leaked names,
    or organization-specific strings declared in a pattern file.
    """
    root = Path(project).resolve()
    report = Report()
    patterns = _load_patterns(pattern_file, inline_patterns, include_builtins=include_builtins)
    if not patterns:
        report.record_skip(str(root), "No grep patterns configured and built-ins disabled.")
        return report, GrepAuditSummary(scanned_files=0, patterns=0, matches=0, skipped_files=1)

    global_include = tuple(include) or ("**/*",)
    global_exclude = tuple(_DEFAULT_EXCLUDES | set(exclude))
    scanned = 0
    skipped = 0
    matches = 0
    for path in _iter_text_files(root):
        rel = _rel(path, root)
        if not _matches_any(rel, global_include) or _matches_any(rel, global_exclude):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            skipped += 1
            continue
        scanned += 1
        lines = text.splitlines()
        for pattern in patterns:
            if not _matches_any(rel, pattern.include) or _matches_any(rel, pattern.exclude):
                continue
            try:
                regex = re.compile(pattern.regex, pattern.flags)
            except re.error as exc:
                report.add(Issue(
                    file=pattern_file and str(pattern_file) or "<inline-pattern>",
                    category="GREP000: invalid grep pattern",
                    severity=Severity.HIGH,
                    detector="grep_audit",
                    description=f"Pattern {pattern.id!r} is not a valid regular expression: {exc}.",
                    recommendation="Fix the pattern before trusting grep-audit results.",
                    confidence="high",
                    evidence={"pattern_id": pattern.id, "regex": pattern.regex, "error": str(exc)},
                ))
                continue
            for line_no, line in enumerate(lines, start=1):
                if not regex.search(line):
                    continue
                matches += 1
                report.add(Issue(
                    file=rel,
                    category=f"GREP001: {pattern.id}",
                    severity=pattern.severity,
                    detector="grep_audit",
                    description=pattern.description,
                    recommendation=pattern.recommendation,
                    location=line.strip(),
                    line_number=line_no,
                    confidence=pattern.confidence,
                    evidence={
                        "pattern_id": pattern.id,
                        "regex": pattern.regex,
                        "line": line_no,
                        "scope": "builtin" if pattern.id.startswith("grep.") else "custom",
                    },
                ))
                if matches >= max_matches:
                    report.add(Issue(
                        file=str(root),
                        category="GREP010: grep audit match budget exceeded",
                        severity=Severity.HIGH,
                        detector="grep_audit",
                        description=f"grep-audit stopped after reaching max_matches={max_matches}.",
                        recommendation="Narrow the pattern set or fix the widespread matches before treating the report as complete.",
                        confidence="high",
                        evidence={"max_matches": max_matches},
                    ))
                    return FindingCore().process(report).report, GrepAuditSummary(scanned, len(patterns), matches, skipped)
    return FindingCore().process(report).report, GrepAuditSummary(scanned, len(patterns), matches, skipped)


def write_grep_audit_summary(path: str | Path | None, summary: GrepAuditSummary, report: Report) -> None:
    """Write summary JSON; returns None when no path is supplied."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"grep_audit": summary.to_dict(), "audit_summary": report.summary(), "issues": [i.to_dict() for i in report.issues]}, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_patterns(pattern_file: str | Path | None, inline_patterns: Iterable[str], *, include_builtins: bool) -> list[GrepPattern]:
    raw: list[dict[str, Any]] = list(_BUILTIN_PATTERNS) if include_builtins else []
    if pattern_file:
        data = json.loads(Path(pattern_file).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            items = data.get("patterns", [])
        elif isinstance(data, list):
            items = data
        else:
            items = []
        raw.extend(item for item in items if isinstance(item, dict))
    for index, spec in enumerate(inline_patterns):
        if ":::" in spec:
            pid, regex = spec.split(":::", 1)
        else:
            pid, regex = f"inline.{index + 1}", spec
        raw.append({"id": pid.strip() or f"inline.{index + 1}", "regex": regex, "severity": "MEDIUM"})
    return [_coerce_pattern(item) for item in raw]


def _coerce_pattern(data: dict[str, Any]) -> GrepPattern:
    severity_name = str(data.get("severity") or "MEDIUM").upper()
    try:
        severity = Severity(severity_name)
    except ValueError:
        severity = Severity.MEDIUM
    flags = 0
    for flag in data.get("flags", []) if isinstance(data.get("flags", []), list) else []:
        if str(flag).lower() == "ignorecase":
            flags |= re.IGNORECASE
        elif str(flag).lower() == "multiline":
            flags |= re.MULTILINE
    return GrepPattern(
        id=str(data.get("id") or "custom.unnamed"),
        regex=str(data.get("regex") or r"$^"),
        severity=severity,
        description=str(data.get("description") or "Configured grep pattern matched."),
        recommendation=str(data.get("recommendation") or "Review the match and document an intentional exception only if it is safe."),
        confidence=str(data.get("confidence") or "medium"),
        include=tuple(data.get("include") or ("**/*",)),
        exclude=tuple(data.get("exclude") or ()),
        flags=flags,
    )


def _iter_text_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        if any(part in DEFAULT_IGNORED_DIRS for part in rel_parts):
            continue
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix in BINARY_EXTENSIONS:
            continue
        if suffix in _TEXT_EXTENSIONS or name.startswith(".env") or name in {"dockerfile", "makefile", "codeowners"}:
            yield path


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    normalized = path.replace("\\", "/")
    for pattern in patterns:
        pat = str(pattern).replace("\\", "/")
        if pat == "**/*":
            return True
        if fnmatch.fnmatch(normalized, pat) or fnmatch.fnmatch("/" + normalized, pat):
            return True
        if pat.startswith("**/") and fnmatch.fnmatch(normalized, pat[3:]):
            return True
        if "/**/" in pat:
            prefix, suffix = pat.split("/**/", 1)
            if normalized.startswith(prefix.rstrip("/") + "/") and fnmatch.fnmatch(normalized[len(prefix.rstrip("/")) + 1 :], suffix):
                return True
        try:
            if Path(normalized).match(pat):
                return True
        except ValueError:
            continue
    return False


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)
