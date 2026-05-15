<!-- ai-code-filter-historical-versions: true -->
# Property-style Fuzz Suite v0.38

`fuzz-suite` adds deterministic generated cases for path, manifest and percent-encoding ambiguity. It complements fixed adversarial fixtures by generating encoded separator depths, Unicode-confusable examples and safe controls.

```bash
ai-code-filter fuzz-suite --ci --summary-json fuzz_summary.json
```
