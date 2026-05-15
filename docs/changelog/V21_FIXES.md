<!-- ai-code-filter-historical-versions: true -->
# v0.23 Fixes

This release fixes the v20 dogfooding defect where `release-audit --adversarial-suite` could exceed practical execution limits because the CLI behavior matrix performed heavy nested scans while adversarial fixtures were also running.

## Changes

- Bounded each CLI matrix command with shorter timeouts.
- Replaced heavy nested `analyze` matrix target with a tiny temporary Python file.
- Replaced recursive full-project nested `release-audit` matrix target with a tiny valid release fixture.
- Kept `type-check --ci` behavior validation, but against the temporary matrix directory.
- Updated package, docs and tests to v0.23.0.

## Acceptance

- `python -m pytest -q`: 109 passed.
- `release-audit . --adversarial-suite`: clean on a cache-free release tree.
- Full zip dogfooding is expected to complete without requiring `--skip-cli-matrix`.
