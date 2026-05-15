<!-- ai-code-filter-historical-versions: true -->
# v0.32 External Audit Hardening

This release adds regression coverage for another external audit wave focused on corruption/integrity blind spots that were not covered by v0.25:

- manifest home shorthand paths, Unicode slash-like separators and superscript Windows device names;
- tree path checks for the same path-portability bypasses;
- Unicode normalization collisions in release trees and zip archives;
- JSON duplicate-key ambiguity;
- XML DOCTYPE/ENTITY declarations;
- Markdown HTML `href`/`src` internal links;
- zip directory entries, duplicate directories and case-insensitive directory collisions;
- missing-root handling for `generate-manifest`.

These checks are now represented as tests in `tests/test_v32_external_audit_hardening.py`.
