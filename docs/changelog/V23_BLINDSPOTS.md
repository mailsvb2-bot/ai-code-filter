<!-- ai-code-filter-historical-versions: true -->
# v0.23 Blind-Spot Acceptance Additions

- Added `ai_code_filter/blindspots.py`.
- Added `blindspot-suite` CLI command.
- Added `release-audit --blindspot-suite` integration.
- Added 25 blind-spot regression fixtures for previously missed manifest, path, Markdown, pyproject, dependency and zip edge cases.
- Added tests ensuring the suite runs in CI and writes nested report outputs.
