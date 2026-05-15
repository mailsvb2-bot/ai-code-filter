# AI Code Filter v49 — Semantic Pytest Completeness

This release adds an optional semantic completeness layer for `pytest-audit`.

Command:

```bash
python ai_filter.py pytest-audit . --semantic-completeness --ci
```

The audit is heuristic, not a proof of full behavioral coverage. It checks whether tests reference production modules/symbols, whether public API reference coverage is suspiciously low, whether complex/error-path production symbols lack direct test references, whether explicit raise paths have exception assertions, and whether assertions are weak/decorative.

Verification snapshot:

- compileall: OK
- pytest: 314 passed, 7 warnings
- pytest-audit static-only: No problems found
- self-analyze: No problems found
- truthfulness-gate: No problems found
- config-contract: No problems found
- db-consistency: No problems found
- rule-ownership: No problems found
- performance-budget: No problems found
- release-audit directory: No problems found
