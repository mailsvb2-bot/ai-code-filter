# CI outputs

AI Code Filter can emit several report formats from the same analysis run:

```bash
ai-code-filter analyze . \
  --no-ai \
  --no-drift \
  --ci \
  --output report.json \
  --sarif report.sarif \
  --junit report.xml \
  --markdown report.md \
  --html report.html
```

- `report.json` is the native machine-readable report.
- `report.sarif` is SARIF 2.1.0 for code scanning tools.
- `report.xml` is JUnit XML for CI test report views.
- `report.md` is a human review report.
- `report.html` is a standalone review artifact.

Use `--no-drift` in ephemeral CI jobs when you do not want the job to update `.ai-code-filter/drift_history.json`.
