from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Analyzer
from ..models import FilePayload, Issue, Severity

JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}


@dataclass(frozen=True)
class _Line:
    number: int
    text: str


class JavaScriptStructureAnalyzer(Analyzer):
    """Structured JS/TS fallback scanner.

    This is intentionally honest: it is not a full ECMAScript AST. It strips comments,
    keeps line numbers, tracks short local windows, and detects high-signal browser risks
    without pretending to understand every JS/TS construct.
    """

    name = "javascript_structure"

    def analyze(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix.lower() not in JS_SUFFIXES:
            return []
        stripped = _strip_comments_preserve_lines(payload.content)
        raw_lines = [_Line(i, line) for i, line in enumerate(payload.content.splitlines(), start=1)]
        code_lines = [_Line(i, line) for i, line in enumerate(stripped.splitlines(), start=1)]
        issues: list[Issue] = []
        issues.extend(self._post_message_wildcard(payload, code_lines))
        issues.extend(self._message_listener_without_origin_check(payload, code_lines))
        issues.extend(self._location_assignment_from_params(payload, code_lines))
        issues.extend(self._string_timer(payload, code_lines))
        issues.extend(self._open_redirect_window_open(payload, code_lines))
        issues.extend(self._document_domain_assignment(payload, code_lines))
        issues.extend(self._raw_dom_xss_sinks(payload, raw_lines, code_lines))
        return _dedupe(issues)

    def _post_message_wildcard(self, payload: FilePayload, lines: list[_Line]) -> list[Issue]:
        pat = re.compile(r"\.postMessage\s*\([^\n,]+,\s*['\"]\*['\"]")
        return [_issue(payload, "JSSTR001: postMessage wildcard target", Severity.HIGH, line, "postMessage uses '*' as target origin.", "Set an explicit trusted origin instead of '*'.") for line in lines if pat.search(line.text)]

    def _message_listener_without_origin_check(self, payload: FilePayload, lines: list[_Line]) -> list[Issue]:
        issues: list[Issue] = []
        for idx, line in enumerate(lines):
            if "addEventListener" not in line.text or "message" not in line.text:
                continue
            window = "\n".join(item.text for item in lines[idx:min(len(lines), idx + 20)])
            if not _has_origin_guard(window):
                issues.append(_issue(payload, "JSSTR002: message listener without origin check", Severity.HIGH, line, "message event listener has no nearby origin allow-list check.", "Check event.origin against an explicit allow-list before reading event.data."))
        return issues

    def _location_assignment_from_params(self, payload: FilePayload, lines: list[_Line]) -> list[Issue]:
        issues: list[Issue] = []
        params_re = re.compile(r"new\s+URLSearchParams|URLSearchParams\(|location\.search")
        assign_re = re.compile(r"(?:window\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=|\()")
        seen_params_nearby: list[int] = []
        for line in lines:
            if params_re.search(line.text):
                seen_params_nearby.append(line.number)
            if assign_re.search(line.text) and any(0 <= line.number - n <= 14 for n in seen_params_nearby):
                issues.append(_issue(payload, "JSSTR003: URL parameter redirect sink", Severity.MEDIUM, line, "location assignment occurs near URLSearchParams/location.search usage.", "Validate redirect targets against an allow-list before assigning location."))
        return issues

    def _string_timer(self, payload: FilePayload, lines: list[_Line]) -> list[Issue]:
        pat = re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]")
        return [_issue(payload, "JSSTR004: string timer execution", Severity.HIGH, line, "setTimeout/setInterval receives a string argument.", "Pass a function reference instead of executable string code.") for line in lines if pat.search(line.text)]

    def _open_redirect_window_open(self, payload: FilePayload, lines: list[_Line]) -> list[Issue]:
        issues: list[Issue] = []
        params_lines: list[int] = []
        for line in lines:
            if re.search(r"URLSearchParams|location\.search|\.searchParams\.get", line.text):
                params_lines.append(line.number)
            if re.search(r"\bwindow\.open\s*\(", line.text) and any(0 <= line.number - n <= 14 for n in params_lines):
                issues.append(_issue(payload, "JSSTR005: URL parameter window.open sink", Severity.MEDIUM, line, "window.open is called near URL parameter extraction.", "Validate and normalize the target URL against an allow-list."))
        return issues

    def _document_domain_assignment(self, payload: FilePayload, lines: list[_Line]) -> list[Issue]:
        pat = re.compile(r"\bdocument\.domain\s*=")
        return [_issue(payload, "JSSTR006: document.domain relaxation", Severity.HIGH, line, "document.domain assignment weakens same-origin isolation.", "Avoid document.domain; use postMessage with strict origin checks or modern isolation headers.") for line in lines if pat.search(line.text)]

    def _raw_dom_xss_sinks(self, payload: FilePayload, raw_lines: list[_Line], lines: list[_Line]) -> list[Issue]:
        issues: list[Issue] = []
        tainted_names: dict[str, int] = {}
        source_re = re.compile(r"\b(const|let|var)\s+([A-Za-z_$][\w$]*)\s*=.*(?:location\.search|URLSearchParams|\.searchParams\.get|localStorage\.getItem|sessionStorage\.getItem)")
        sink_re = re.compile(r"\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*(?:=|\()")
        for raw, line in zip(raw_lines, lines):
            m = source_re.search(line.text)
            if m:
                tainted_names[m.group(2)] = line.number
            if sink_re.search(line.text):
                if any(name in line.text and 0 <= line.number - src_line <= 20 for name, src_line in tainted_names.items()):
                    issues.append(_issue(payload, "JSSTR007: DOM XSS parameter-to-HTML sink", Severity.HIGH, raw, "Tainted browser-controlled value reaches raw HTML DOM sink.", "Use textContent/safe DOM APIs or sanitize with a reviewed HTML sanitizer."))
        return issues


def _has_origin_guard(window: str) -> bool:
    origin = re.search(r"\b(?:event|e)\.origin\b|\borigin\b", window)
    if not origin:
        return False
    allowlist = re.search(r"includes\s*\(|===|!==|Set\s*\(|allowedOrigins|trustedOrigins|ALLOWED_ORIGINS", window)
    return bool(allowlist)


def _issue(payload: FilePayload, category: str, severity: Severity, line: _Line, description: str, recommendation: str) -> Issue:
    return Issue(
        file=payload.relative_path,
        category=category,
        severity=severity,
        detector="javascript_structure",
        description=description,
        recommendation=recommendation,
        location=line.text.strip(),
        line_number=line.number,
    )


def _strip_comments_preserve_lines(source: str) -> str:
    out: list[str] = []
    i = 0
    state = "code"
    quote = ""
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if ch in {'"', "'", "`"}:
                quote = ch
                state = "string"
                out.append(ch)
            elif ch == "/" and nxt == "/":
                state = "line_comment"
                out.extend([" ", " "])
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                out.extend([" ", " "])
                i += 1
            else:
                out.append(ch)
        elif state == "string":
            out.append(ch)
            if ch == "\\" and i + 1 < len(source):
                i += 1
                out.append(source[i])
            elif ch == quote:
                state = "code"
        elif state == "line_comment":
            if ch == "\n":
                out.append("\n")
                state = "code"
            else:
                out.append(" ")
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                out.extend([" ", " "])
                i += 1
                state = "code"
            elif ch == "\n":
                out.append("\n")
            else:
                out.append(" ")
        i += 1
    return "".join(out)


def _dedupe(issues: list[Issue]) -> list[Issue]:
    seen: set[tuple[str, str, int | None]] = set()
    out: list[Issue] = []
    for issue in issues:
        key = (issue.file, issue.category, issue.line_number)
        if key in seen:
            continue
        seen.add(key)
        out.append(issue)
    return out
