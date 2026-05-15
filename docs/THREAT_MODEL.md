# Threat model

AI Code Filter is a defensive code-audit CLI. Static analysis commands do not execute audited application code. Execution gates such as `behavior-audit`, `coverage-audit`, and `mutation-audit` intentionally run project code/tests and must be treated as trusted-workspace operations.

## Trust boundaries

- Audited source files are untrusted input.
- LLM output is advisory and never the only source of truth.
- Deterministic rules are versioned code and should be covered by tests.
- Suppressions are risk acceptances and require owner, reason, and expiry.

## Execution-gate safety policy

For untrusted repositories, use static gates first:

```bash
ai-code-filter analyze . --no-ai --no-drift --ci
ai-code-filter release-audit artifact.zip --ci
```

Only run execution gates against trusted code or inside an external OS/container sandbox. For `behavior-audit`, prefer:

```bash
ai-code-filter behavior-audit . --spec behavior.json --strict-sandbox --ci
```

`--strict-sandbox` bundles Python socket blocking, command-probe disabling, and secret-like environment stripping. This is a safer subprocess policy, not a kernel sandbox and not a guarantee against hostile native code.

## Current guarantees

- Failed analyzer execution is reported as an issue, not silently hidden.
- Drift state is stored under `.ai-code-filter/` unless configured otherwise.
- CI outputs include SARIF, JUnit XML, Markdown, HTML, and native JSON.
- Quality gates can fail builds by severity budget or by new issues versus a baseline.

## Non-goals / limitations

- No full-program Python type inference.
- No kernel/container sandbox. Behavior, coverage and mutation gates execute code and require caller isolation for untrusted repositories.
- Python data-flow is intra-function and conservative.
- JS/TS structure analysis is a deterministic fallback, not a full ECMAScript parser.
- False positives and false negatives are still possible; benchmark coverage must grow with real projects.
