<!-- ai-code-filter-historical-versions: true -->
# Code Array / Registry / Policy Ambiguity Acceptance v0.38

AI Code Filter v0.38 adds `array-ambiguity-suite` and the `ArrayAmbiguityAnalyzer` for ambiguity inside source-code arrays and configuration registries.

It checks duplicate scalar arrays, duplicate array-of-pairs keys, duplicate identifiers in arrays of objects/dicts, conflicting allow/deny entries, wildcard-before-specific ordering, contradictory boolean flags, JSON registry ambiguity and JavaScript/TypeScript dispatch arrays.

```bash
ai-code-filter array-ambiguity-suite --ci
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --array-ambiguity-suite --ci
```
