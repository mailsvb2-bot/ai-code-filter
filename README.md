<!-- ai-code-filter-historical-versions: true -->
# AI Code Filter — Refactored Architecture v0.59.0

Layered deterministic audit CLI evolved through the v38–v59 hardening line. It separates pipeline orchestration, file loading, deterministic rules, data-flow checks, JavaScript structure checks, LLM adapter, drift storage, governance, reporting, release-audit and CI scorecard surfaces. The current package version is v0.59.0; older v0.38 sections below are historical lineage notes, not the current release label.

## Architecture

- `cli.py` — argument parsing and command dispatch only.
- `pipeline.py` — orchestration only.
- `models.py` — issue/report contracts.
- `filesystem.py` — file collection, ignored directories, size limits, validation.
- `llm/` — OpenAI adapter and prompts.
- `guards/` — response quality guards.
- `analyzers/` — deterministic analyzers, including Python data-flow-lite and JS/TS structure scan.
- `rules/` — explicit deterministic rule catalog with tested rule ids.
- `policy.py` — suppressions, severity budgets, baseline gating, stable fingerprints.
- `artifacts.py` — SARIF, JUnit XML, Markdown, HTML reports.
- `benchmarks.py` — built-in positive/negative benchmark fixtures.
- `drift.py` — persistent drift history under `.ai-code-filter/`.
- `reporting.py` — console/JSON output.

## Recommended CI gate pack

```bash
python -m compileall -q ai_code_filter ai_filter.py
python -m pytest -q
python ai_filter.py benchmark --ci
python ai_filter.py analyze . --no-ai --no-drift --ci
python ai_filter.py quality-matrix . --ci
python ai_filter.py scorecard . --ci
python ai_filter.py release-audit ./release.zip --ci
```

Use stricter optional gates when the required tools are installed and the project is trusted: `type-audit`, `external-audit`, `coverage-audit`, `mutation-audit`, and `behavior-audit --strict-sandbox`.

## Usage

```bash
python ai_filter.py analyze ./my_project --no-ai --workers 4
python ai_filter.py analyze ./my_project --output report.json --sarif report.sarif --ci
python ai_filter.py analyze ./my_project --baseline-report previous.json --fail-on-new HIGH --ci
python ai_filter.py analyze ./my_project --suppressions suppressions.json --max-high 0 --ci
python ai_filter.py baseline ./my_project --baseline ./etalon
python ai_filter.py drift-check ./my_project
python ai_filter.py list-rules --json coverage.json
python ai_filter.py benchmark --output benchmark.json --ci
```

Use `--no-ai` for deterministic local analysis without OpenAI.

## Deterministic catalog status

Current explicit rule catalog: 39 deterministic rules plus analyzer capabilities documented in coverage output.

- Python: `PY001`–`PY028`
- Text hygiene: `TXT001`–`TXT003`
- JavaScript/TypeScript: `JS001`–`JS008`

Additional analyzer capabilities beyond the catalog:

- `PYDF001` — data-flow SQL injection, local plus helper-return summaries.
- `PYDF002` — data-flow command injection, local plus helper-return summaries.
- `PYDF003` — data-flow raw template/HTML sink, local plus sanitizer awareness.
- `JSSTR001` — postMessage wildcard target origin.
- `JSSTR002` — message listener without nearby origin allow-list check.
- `JSSTR003` — URL parameter redirect sink.
- `JSSTR004` — string-based setTimeout/setInterval execution.
- `JSSTR005` — URL parameter to window.open sink.
- `JSSTR006` — document.domain relaxation.
- `JSSTR007` — browser-controlled value to raw HTML DOM sink.

The catalog is intentionally explicit. The project does not claim “1000+ rules” unless those rules exist as implemented, testable detectors.

## Governance features

- Plugin API: `--plugin plugin.py` loads external deterministic rules.
- Severity budgets: `--max-critical`, `--max-high`, `--max-medium`, `--max-low`.
- Baseline gating: `--baseline-report previous.json --fail-on-new HIGH`.
- Suppression governance: `--suppressions suppressions.json` requires owner, reason and non-expired date.
- Rule coverage matrix: `ai-code-filter list-rules --json coverage.json`.
- Stable fingerprints: `--print-fingerprints` helps create baselines and suppressions deliberately.


## v0.38 evidence artifact safety

v0.38 adds `evidence-artifact-safety-suite` and `validate-evidence-artifact-safety` so fixes/audit reports cannot use unsafe evidence paths, remote artifact references, shell-injected verification commands, placeholder reviewers, future review dates, unsafe `test_path` values, non-canonical versions or non-final fixes statuses.

```bash
ai-code-filter evidence-artifact-safety-suite --ci
ai-code-filter validate-evidence-artifact-safety fixes.json --ci
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --evidence-artifact-safety-suite --ci
```

## v0.38 analysis-core features

- Python data-flow-lite analyzer for direct source → sink paths inside one function.
- JavaScript/TypeScript structure analyzer for browser message/origin and redirect sinks.
- Built-in benchmark command with positive and negative expectations.
- Threat-model and benchmark documentation.
- Test suite expanded to cover data-flow, JS structure, and benchmark behavior.

## Production-readiness boundary

This project is a **CI/helper quality gate**, not a proof engine and not a sandbox. Treat these statements as contractual:

- `TOTAL=0` means the configured checks found no reportable findings; it does **not** prove production readiness.
- The internal scorecard is an internal deterministic gate, not an external certification.
- Optional external tools that are not installed must be reported as skipped/accepted risk, not success.
- `behavior-audit`, `coverage-audit`, and `mutation-audit` execute project code/tests. Use them only on trusted projects or inside an external OS/container sandbox.
- For untrusted repositories, start with static commands such as `analyze --no-ai --no-drift` and `release-audit`; for behavior probes use `--strict-sandbox` and external isolation.

Recommended hardened behavior command:

```bash
ai-code-filter behavior-audit . --spec behavior.json --strict-sandbox --ci
```

`--strict-sandbox` bundles Python socket blocking, command-probe disabling, and secret-like environment stripping. It is still a subprocess policy, not a kernel sandbox.

## Honest limitations

- Python data-flow is still conservative and summary-based; it is not full-program taint analysis.
- JavaScript/TypeScript structure analysis is an honest fallback scanner, not a full ECMAScript AST parser.
- Benchmark metrics are expectation-level metrics on small built-in fixtures, not real-world precision claims.
- The LLM layer is optional and should be treated as review assistance, not the source of truth.
- Deterministic rules can still produce false positives and false negatives.

## Verification

```bash
python -m compileall -q ai_code_filter ai_filter.py
python -m pytest -q
python ai_filter.py benchmark --output benchmark.json --ci
python ai_filter.py analyze . --no-ai --no-drift
```

Historical v0.38 packaging note: `263 passed`, self-report `TOTAL=0`. Current v0.58.x releases must be verified from a fresh checkout with the commands below; do not reuse historical counts as release evidence.


## v0.38 additions

- Cross-file Python data-flow lite (`PYXDF001`–`PYXDF003`).
- Multi-file benchmark fixtures.
- Stable pytest configuration with local `pythonpath`.
- Documented limits in `docs/CROSS_FILE_DATAFLOW.md`.

## v0.38 closure additions

- AI prompt catalog now contains 52 categories and 1040 concrete example situations.
- Chain inspector is restored as a first-class analyzer: module chains, stereotype score and unknown-call ratio.
- Pipeline integrity self-check verifies `record_drift` remains wired into `AnalysisPipeline.analyze_paths`.
- Fatigue and polite-annoyance detectors now include error-handling absence and branching-entropy anomaly.
- `docs/COMPLIANCE_MATRIX.md` records which original prototype promises are fully, partially or additionally covered.

### Type resolution and external SDK knowledge (v0.38)

The filter has a safe type-resolution layer:

- `inspect-deps` reads `pyproject.toml`, requirements files, `package.json`, and lockfiles without importing project code.
- `index-sdk` builds an SDK symbol index. By default it only checks module availability; `--import-packages` is opt-in because importing third-party packages can have side effects.
- `type-check` bridges to installed `pyright` and `mypy` when available and converts diagnostics into the unified report model.
- `analyze --sdk-index --unknown-call-check` enables conservative SDK attribute validation. It reports only high-confidence missing public SDK attributes from the local SDK index.

This does not replace Pyright/Mypy/TypeScript. It gives the auditor a safer resolver boundary so unknown-call findings are not guessed from text alone.


## v0.38 integrity features

- `generate-manifest` writes a SHA256 manifest for release trees.
- `verify-manifest` detects missing, changed and stray files.
- `release-audit` now validates zip CRC, text encodings, structured JSON/TOML/XML files, Markdown links and critical empty files.

## v0.38 blind-spot acceptance

v0.38 adds a permanent blind-spot regression layer for defects that earlier releases missed during external acceptance:

```bash
ai-code-filter blindspot-suite --ci --output blindspots.json
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --blindspot-suite --ci
```

This suite checks manifest parser bypasses, symlink-backed manifest entries, release-noise directories, Markdown path edge cases, structured pyproject parsing, optional dependency classification, and zip path ambiguity.

## v0.38 structured hardening acceptance

v0.38 adds a dedicated `structured-hardening-suite` for Unicode/path-confusable and structured-file bypass classes:

```bash
ai-code-filter structured-hardening-suite --ci --output structured_hardening.json
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --structured-hardening-suite --ci
```

The suite covers Unicode slash confusables, `~/` shorthand paths, superscript Windows device names, Unicode-normalized collisions, duplicate JSON keys, XML DTD/entity declarations, embedded HTML links in Markdown, unsafe zip directory entries, and OS trash files.

## v0.38 encoded collision hardening

v0.38 adds a dedicated `encoded-collision-hardening-suite` for encoded separator ambiguity,
manifest collision consistency and structured duplicate key edge cases:

```bash
ai-code-filter encoded-collision-hardening-suite --ci
ai-code-filter release-audit ai_code_filter_refactored_v38.zip \
  --adversarial-suite \
  --blindspot-suite \
  --path-portability-suite \
  --structured-hardening-suite \
  --encoded-collision-hardening-suite \
  --ci
```

## v0.38 provenance honesty acceptance

v0.38 adds `provenance-honesty-suite` so audit/fix artifacts must distinguish tool-detected findings from external review findings, blind spots and regression fixtures.

```bash
ai-code-filter provenance-honesty-suite --ci
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --provenance-honesty-suite --ci
```


### Pytest semantic completeness audit

`pytest-audit` can optionally run a heuristic semantic completeness pass:

```bash
python ai_filter.py pytest-audit . --semantic-completeness --ci
```

This pass does not claim to prove full behavioral coverage. It checks practical signals: whether tests import/reference production modules and public symbols, whether public API reference coverage is suspiciously low, whether complex/error-path production symbols lack direct test references, whether explicit `raise` paths have exception assertions, and whether assertions are weak/decorative.

Useful options:

```bash
python ai_filter.py pytest-audit . --semantic-completeness --min-public-coverage 0.50 --summary-json pytest_summary.json
```


## Behavior audit

`behavior-audit` executes explicit production behavior contracts in isolated subprocesses with per-probe timeouts. It supports import probes, function probes with JSON args/kwargs, expected exceptions, and command probes. This is a behavioral CI smoke layer, not a proof of full production correctness.

Example contract:

```json
{
  "probes": [
    {"type": "function", "name": "add works", "target": "app:add", "args": [2, 3], "expect": {"equals": 5}},
    {"type": "function", "name": "empty parse fails", "target": "app:parse", "args": [""], "expect": {"raises": "ValueError"}},
    {"type": "command", "name": "cli help", "cmd": ["python", "-m", "app.cli", "--help"], "expect": {"exit_code": 0, "stdout_contains": "usage"}}
  ]
}
```

Run:

```bash
python ai_filter.py behavior-audit . --spec behavior.json --timeout 10 --summary-json behavior_summary.json --ci
python ai_filter.py behavior-audit . --import-smoke --ci
```

### Project Call Graph Core

Build a deterministic Python call graph with symbol/index evidence and unknown-call accounting:

```bash
python ai_filter.py call-graph . --output callgraph.json --ci --max-unknown-ratio 0.25
```

The graph records functions, classes, methods, direct/internal/external call edges, simple constructor-bound method calls, import/re-export aliases, and dynamic/unknown calls. It is intentionally bounded: runtime DI, deep inheritance/MRO, monkeypatching, decorator signature rewriting, and dynamic `getattr`/`importlib` dispatch are reported as limitations/unknowns rather than guessed as facts.

### Quality gates toward reference-grade CI

This release adds three gates that raise confidence beyond static findings:

```bash
python ai_filter.py coverage-audit . --min-lines 80 --min-branches 70 --summary-json coverage_summary.json --ci
python ai_filter.py mutation-audit . --max-mutants 20 --summary-json mutation_summary.json --ci
python ai_filter.py behavior-audit . --spec behavior.json --deny-network --no-command-probes --ci
```

`coverage-audit` runs `coverage.py run --branch -m pytest` and fails budgets for line/branch coverage. `mutation-audit` creates a temporary project copy, applies conservative boolean/comparison mutants, runs pytest for each mutant, and reports surviving mutants. These gates still do not prove complete correctness; they expose weak execution coverage and weak behavior assertions that ordinary green pytest can miss.

Behavior probes now have optional sandbox hardening flags. `--deny-network` blocks Python-probe socket creation and marks subprocess environments as network-disabled; `--no-command-probes` disables command probes when a stricter review environment is required. This is partial sandboxing, not a secure VM for untrusted code.

## Production-readiness gates

This version includes optional production-readiness gates. These are CI helpers, not proofs of production correctness:

```bash
python ai_filter.py type-audit . --engine pyright --engine mypy --ci
python ai_filter.py external-audit . --tool ruff --tool bandit --tool semgrep --tool pip-audit --ci
python ai_filter.py deployment-audit . --ci
python ai_filter.py migration-audit . --ci
python ai_filter.py supply-chain-audit . --ci
python ai_filter.py coverage-audit . --max-uncovered-files 10 --ci
python ai_filter.py mutation-audit . --min-score 60 --ci
python ai_filter.py behavior-audit . --spec behavior.json --deny-network --deny-secret-env --env-allowlist APP_ENV --ci
```

The gates normalize findings through `FindingCore`. Missing external tools are reported as skips unless `--require-tools` is used.


## V54 quality amplification gates

This release adds three meta-gates that strengthen every existing audit direction without claiming impossible 100% guarantees:

```bash
python ai_filter.py precision-audit tests/golden --ci
python ai_filter.py stress-audit --files 1000 --max-seconds 30 --max-peak-mb 512 --ci
python ai_filter.py quality-matrix . --summary-json quality_matrix.json --ci
```

`precision-audit` uses a golden corpus contract: files under `clean/` must stay clean, and `expected.json` can declare known-bad fixtures that must keep producing specific finding signals. This protects both false-positive and false-negative regressions.

`stress-audit` builds a synthetic large Python project, runs the analyzer and call-graph builder, and enforces time, memory and unknown-call budgets. It is a deterministic stress smoke, not a substitute for running against the user's largest real repositories.

`quality-matrix` orchestrates the core deterministic governance gates — truthfulness, config, DB consistency, rule ownership, deployment, migration and supply-chain — and preserves every finding through `FindingCore` with gate provenance.


### Expanded quality surfaces

```bash
python ai_filter.py analyze . --profile fastapi --profile flask --profile django --profile sqlalchemy --ci
python ai_filter.py rule-quality . --summary-json rule_quality.json --ci
```

This release expands project-specific profiles beyond Messaging/Autonomy with lightweight FastAPI, Flask, Django and SQLAlchemy risk checks. It also adds `rule-quality`, a rule passport gate that verifies each rule documents status, precision, coverage modes, known gaps and test-evidence references. This does not prove perfect precision/recall; it prevents silent rule-quality claims without reviewable metadata.

## neutralized real-world regression surfaces

This release removes project-branded profile names from the public audit surface. The domain-oriented profiles are now neutral:

- `messaging-bot` for generic webhook/polling bot runtime risks.
- `autonomy-canon` for generic canonical-decision / guarded-execution architecture risks.

New gates:

```bash
python ai_filter.py golden-fixtures tests/golden --ci
python ai_filter.py external-normalize --tool semgrep --input semgrep.json --ci
python ai_filter.py external-normalize --tool bandit --input bandit.json --ci
python ai_filter.py external-normalize --tool ruff --input ruff.json --ci
python ai_filter.py external-normalize --tool pyright --input pyright.json --ci
python ai_filter.py zip-fixture-audit . --ci
python ai_filter.py compatibility-audit . --ci
python ai_filter.py ownership-conflicts . --ci
```

`golden-fixtures` supports real-world and framework-specific expected fixtures through `tests/golden/fixtures.json`. `external-normalize` converts Semgrep, Bandit, Ruff and Pyright JSON output into native findings so external tools can flow through `FindingCore`. `zip-fixture-audit` distinguishes intentional duplicate zip-entry fixtures from accidental archive corruption. `compatibility-audit` protects the public CLI regression surface. `ownership-conflicts` detects contradictory owner signals and governance-bypass language in production code.

## Grep/pattern audit gate

```bash
python ai_filter.py grep-audit . --ci
python ai_filter.py grep-audit . --pattern-file docs/GREP_AUDIT_PATTERNS.json --ci
python ai_filter.py grep-audit . --regex 'public.forbidden_name:::LegacyBrand' --ci
```

`grep-audit` adds a deterministic repository-wide regex gate for classes of issues that are better expressed as literal or regular-expression contracts than AST rules: unresolved merge-conflict markers, private key material, forbidden public names, legacy markers, migration stop-words, or organization-specific banned strings. Custom patterns are supplied through JSON with `id`, `regex`, `severity`, `include`, `exclude`, `description`, `recommendation` and optional regex `flags`. Every match is normalized as an `Issue` and passes through `FindingCore`, so SARIF/JUnit/Markdown/HTML outputs and CI exit behavior are consistent with the rest of the engine.

This is intentionally not a replacement for Semgrep/Bandit/Ruff/Pyright or typed AST analysis. It is a fast, explicit, reviewable grep-class quality gate for repository policy, public naming hygiene, secret-like literals and compatibility regressions.

## CI/audit scorecard extensions

Additional deterministic gates:

```bash
python ai_filter.py policy-audit . --ci
python ai_filter.py ci-profile-audit . --ci
python ai_filter.py release-evidence . --ci
python ai_filter.py changed-files-audit . --changed-file ai_code_filter/cli.py --ci
python ai_filter.py scorecard . --min-score 90 --ci
```

These gates add policy-as-code, machine-readable CI profiles, release evidence coverage, changed-file scoped analysis and a scorecard meta-report. They are quality gates, not mathematical proof of arbitrary project correctness.
