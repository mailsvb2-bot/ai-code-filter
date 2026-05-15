<!-- ai-code-filter-historical-versions: true -->
# Release Audit v0.38

`release-audit` checks the release artifact as a product, not only as source code.
It is designed to catch the classes of defects that a normal static code scan can miss.

## What it checks

- package version consistency across `pyproject.toml` and `ai_code_filter.__version__`
- stale version mentions in README/docs
- zip archive root naming versus release version
- cache/build/runtime garbage in the release tree
- JUnit/SARIF/Markdown semantic invariants for failed/skipped analysis
- coverage matrix reconciliation
- CLI behavior matrix for commands that write nested output files
- `type-check --ci` failure semantics when required tools are skipped

## Usage

```bash
ai-code-filter release-audit dist/ai_code_filter_refactored_v16.zip --ci
ai-code-filter release-audit . --skip-cli-matrix --output release_audit.json
```

## Boundary

`release-audit` does not replace `analyze`. Use both:

```bash
ai-code-filter analyze . --no-ai --no-drift --ci
ai-code-filter release-audit dist/ai_code_filter_refactored_v16.zip --ci
```
