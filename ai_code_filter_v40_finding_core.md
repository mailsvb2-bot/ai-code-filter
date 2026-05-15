# AI Code Filter v40 — FindingCore hardening

## Implemented

- Added `ai_code_filter/finding_core.py` as the single post-analysis decision center for findings.
- Centralized:
  - issue normalization;
  - stable fingerprints;
  - deduplication;
  - suppression loading/validation/application;
  - baseline/new issue gate;
  - quality budgets;
  - CI exit decision helper.
- Kept `ai_code_filter/policy.py` as a compatibility facade delegating to `FindingCore`, avoiding a second decision layer.
- Updated CLI governance path to use `FindingCore.process(...)`.
- Added regression tests covering:
  - dedupe + evidence normalization;
  - suppression before quality gate;
  - baseline gate using the same fingerprint semantics.

## Verification

- `python -m compileall -q ai_code_filter ai_filter.py`
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q`
- `python ai_filter.py analyze . --no-ai --no-drift --ci`
- `python ai_filter.py release-audit . --ci`

## Honest status

This is not a large Canonical Autonomy-style DecisionCore. It is a deliberately small FindingCore for this tool's scope: raw findings -> normalized issues -> governance -> report/exit policy.
