<!-- ai-code-filter-historical-versions: true -->
# Integrity / Corruption Audit v0.38

AI Code Filter v0.38 adds an artifact integrity layer for release trees and zip archives.
It is separate from normal code scanning because corruption, truncation and broken release metadata are product-level failures.

## Commands

```bash
ai-code-filter generate-manifest . --output MANIFEST.sha256
ai-code-filter verify-manifest . --manifest MANIFEST.sha256 --ci
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --ci
```

## Covered checks

- SHA256 manifest generation and verification.
- Zip CRC validation before extraction.
- Unsafe zip member paths, symlinks and stray top-level files.
- Invalid UTF-8, NUL bytes and binary data masquerading as text.
- JSON, TOML and XML parsing.
- YAML-like indentation and inline collection sanity checks.
- Broken internal Markdown links.
- Case-insensitive path collisions.
- Empty critical files such as `README.md`, `pyproject.toml`, `ai_filter.py` and `ai_code_filter/__init__.py`.
- Unexpected executable bit on Python library modules.
- Mixed line endings and missing final newline warnings.

## Boundary

This layer does not replace static security analysis. It answers a different question:

> Is this shipped artifact complete, parseable, verifiable and unlikely to be corrupted or partially written?
