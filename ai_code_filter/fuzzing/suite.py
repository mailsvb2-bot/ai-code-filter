from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from ..integrity import _unsafe_path_reason
from ..models import Issue, Report, Severity


@dataclass(frozen=True)
class FuzzCase:
    case_id: str
    domain: str
    payload: str
    expected_unsafe: bool
    description: str


def _cases() -> list[FuzzCase]:
    dangerous = [
        "../evil.py", "..%2Fevil.py", "%252e%252e%252Fevil.py", "pkg/docs%2Fguide.md",
        "pkg/%255Csecret.txt", "C:/evil.txt", "~/evil.txt", "pkg/ CON.txt",
        "pkg/COM¹.txt", "pkg/evil：stream", "pkg／evil.txt", "pkg∕evil.txt",
        "pkg/..\u202egnp.py", "pkg/\ufdd0.txt", "pkg/ evil.txt", "pkg/\u00a0evil.txt",
        "pkg/.. /evil.txt", "pkg/. /evil.txt", "pkg/evil.txt ", "pkg/aux.txt",
    ]
    safe = ["pkg/module.py", "docs/guide.md", "tests/test_ok.py", "README.md", "src/app_config.json"]
    result = [FuzzCase(f"PATH_BAD_{i:03d}", "path", value, True, "Generated unsafe path should be rejected") for i, value in enumerate(dangerous, 1)]
    result.extend(FuzzCase(f"PATH_SAFE_{i:03d}", "path", value, False, "Generated safe path should be accepted") for i, value in enumerate(safe, 1))
    # Generated percent-encoding depth checks.
    for depth in range(1, 5):
        payload = "slash"
        encoded = "/"
        for _ in range(depth):
            encoded = quote(encoded, safe="")
        result.append(FuzzCase(f"ENCSEP_{depth:03d}", "encoded_separator", f"pkg{encoded}evil.txt", True, "Encoded separator payload should be rejected"))
    return result


def fuzz_suite_summary() -> dict:
    cases = _cases()
    by_domain: dict[str, int] = {}
    for case in cases:
        by_domain[case.domain] = by_domain.get(case.domain, 0) + 1
    return {
        "schema_version": "1.0",
        "case_count": len(cases),
        "by_domain": dict(sorted(by_domain.items())),
        "cases": [case.__dict__ for case in cases],
    }


def run_fuzz_suite() -> Report:
    report = Report()
    for case in _cases():
        actual_unsafe = _unsafe_path_reason(case.payload) is not None
        if actual_unsafe != case.expected_unsafe:
            report.add(Issue(
                file=f"<fuzz-suite:{case.case_id}>",
                category="Fuzz acceptance",
                severity=Severity.HIGH if case.expected_unsafe else Severity.MEDIUM,
                detector="fuzz_suite",
                description=f"Fuzz case expectation mismatch for {case.payload!r}: expected unsafe={case.expected_unsafe}, got unsafe={actual_unsafe}.",
                recommendation="Update path/integrity validators or correct the fuzz fixture expectation.",
            ))
    return report
