<!-- ai-code-filter-historical-versions: true -->
# Adversarial Acceptance Suite v0.38

`ai-code-filter adversarial-suite` runs built-in malicious/broken fixtures against the release and integrity validators. It is not a scan of the current project; it is a self-test that proves the validators reject known bypass classes.

Covered fixture families:

- malformed and spoofed `MANIFEST.sha256` entries
- missing roots and stale manifests
- invalid JSON / UTF-8 / NUL bytes / BOM / CR-only line endings
- broken inline and reference-style Markdown links
- case-insensitive path collisions
- broken/out-of-root symlinks
- unsafe zip paths, duplicate zip members, symlink entries, empty archives, top-level stray files, suspicious compression ratios
- broken Python syntax in a release tree

Usage:

```bash
ai-code-filter adversarial-suite --ci --output adversarial.json
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --adversarial-suite --ci
```

A clean result means every built-in adversarial fixture was detected by the expected rule family. Any issue means a validator blind spot has reappeared.
