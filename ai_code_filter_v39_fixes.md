# v39 Engine Hardening Fixes

Implemented focused P0/P1 hardening without claiming full static-analysis completeness.

## Added

- Shared `ai_code_filter.symbols` resolver for import aliases, from-import aliases and simple assignment aliases.
- Finding metadata: `confidence` and machine-readable `evidence` in native JSON reports.
- Canonical-call evidence for critical rule-catalog findings.
- Interprocedural-lite data-flow for same-file helper returns through simple assignments.
- Wrapper sink detection for same-file wrappers around shell/SQL sinks.
- Machine-readable limitations registry via `ai-filter limitations` and `docs/LIMITATIONS.json`.
- Config contract audit via `ai-filter config-contract`.
- Documentation truthfulness gate via `ai-filter truthfulness-gate`.
- Baseline write mode: `ai-filter analyze ... --write-baseline baseline.json`.

## Verified

- `python -m compileall -q ai_code_filter ai_filter.py`
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q`
- `python ai_filter.py analyze . --no-ai --no-drift --ci`
- `python ai_filter.py release-audit . --ci`
