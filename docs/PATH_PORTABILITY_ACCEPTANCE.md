<!-- ai-code-filter-historical-versions: true -->
# Path Portability / Archive-Name Bypass Acceptance v0.38

This layer turns cross-platform path ambiguity and archive-name bypasses into a permanent acceptance suite.
It is narrower than the full blind-spot suite and focuses on paths that can be interpreted differently across
operating systems, archive tools, Markdown renderers, or manifest parsers.

## Command

```bash
ai-code-filter path-portability-suite --ci --output path-portability.json
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --path-portability-suite --ci
```

## Covered threat classes

- Windows reserved names such as `CON`, `NUL`, `COM1`, `LPT9`.
- Windows drive and ADS/colon paths such as `C:/evil.txt` or `file:stream`.
- Percent-encoded traversal and backslash payloads.
- Unicode control and format characters, including bidi overrides.
- Case-insensitive path/member collisions.
- Ambiguous manifest path serialization.
- Unsafe Markdown links and reference targets.
- Unsafe zip member names.

The suite is designed to catch the class of defects that previously required manual external audit around
manifest parsing, zip member validation, tree integrity, Markdown target validation, and path normalization.
