<!-- ai-code-filter-historical-versions: true -->
# Blind-Spot Acceptance Suite v0.38

The blind-spot suite turns previously missed audit edge cases into permanent release acceptance fixtures.

It complements the adversarial suite:

- `adversarial-suite` checks broad hostile/corrupt artifacts.
- `blindspot-suite` checks known classes that were previously missed by earlier releases and must not regress.

## Commands

```bash
ai-code-filter blindspot-suite --ci --output blindspots.json
ai-code-filter blindspot-suite --summary-json blindspot_summary.json
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --blindspot-suite --ci
```

## Families covered

- manifest path parsing: Windows drive paths, traversal, ambiguous whitespace, backslashes
- manifest verification: symlink-backed entries and symlink generation bypasses
- release-noise directories: VCS, virtualenvs, dependencies, build outputs
- text integrity: `.rst` truncation/newline normalization
- path collisions: case-insensitive directory/file collisions
- Markdown links: Windows-drive links, backslashes, reference links with titles
- release metadata: directory name/version checks, structured `pyproject.toml` parsing, console-script comments
- dependency contract: optional OpenAI must not be treated as mandatory
- zip integrity: duplicate members, drive paths, backslashes, control chars

## Rule

A manually discovered blind spot must become:

1. a `BlindSpotCase`,
2. an expected detector prefix,
3. a regression test,
4. part of `release-audit --blindspot-suite`.

This prevents "we fixed it once" from becoming an undocumented manual acceptance step.
