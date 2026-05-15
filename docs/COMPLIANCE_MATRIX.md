<!-- ai-code-filter-historical-versions: true -->
# Compliance Matrix v0.38

This matrix checks the original single-file prototype promises against the refactored package. Status meanings:

- **FULL**: implemented in deterministic code or in the AI-review path with validation.
- **PARTIAL**: implemented, but with known limitations or heuristic scope.
- **SUPERSET**: not in the original list, added by the refactor.

| # | Capability | Status | Evidence in v0.38 | Notes |
|---|---|---:|---|---|
| 1 | AI reviewer with GPT-4o assistance | FULL | `ai_code_filter/llm/client.py`, `ai_code_filter/llm/prompts.py` | Optional; skipped honestly when API key/package is unavailable. |
| 1a | 52 categories, 1000+ concrete examples | FULL | `CATEGORY_TITLES`, generated `ERROR_CATALOG` string containing `TOTAL_EXAMPLES: 1040` | Prompt catalog is real and generated from versioned code. |
| 1b | Exact source-code location | FULL | AI issues require exact snippet; local issues include `line_number`/`location` where available | AI findings with missing snippets are dropped. |
| 1c | Concrete fix recommendation | FULL | `Issue.recommendation`; prompt requires actionable recommendations | Report formats preserve recommendation. |
| 2 | Stereotype guard | FULL | `guards/stereotype.py`, `llm/client.py` strict retry | Detects flattery/vague/review prose and retries once with strict prompt. |
| 3 | Chain inspector | FULL | `analyzers/chain_inspector.py` | Restored as a first-class analyzer in v0.38. |
| 3a | Stereotypical code at file level | FULL | `ChainInspectorAnalyzer` + `estimate_stereotype_score` | Flags high index. |
| 3b | Unknown call ratio | PARTIAL+ | `ChainInspectorAnalyzer._unknown_calls`, `UnknownCallValidator`, `type_resolution/*` | Still not a full type checker, but now backed by manifests, optional SDK index and pyright/mypy adapters. |
| 3c | Dependency chains from roots to leaves | FULL | `ChainInspectorAnalyzer.dependency_chains()` | Available programmatically; not yet exported as separate CLI report. |
| 4 | Contract validator | FULL | `python_contract.py`, `pipeline.baseline_check()` | Relative-path comparison fixed versus original prototype. |
| 5 | Drift monitor/regression | FULL | `drift.py`, `pipeline.analyze_paths()` | State lives under `.ai-code-filter/`, not project root. |
| 5a | AI verdict recorded in drift history | FULL | `record_drift(..., verdict)` in `AnalysisPipeline.analyze_paths` | Pipeline integrity verifies this remains wired. |
| 6 | Fatigue detector | FULL | `analyzers/fatigue.py` | Includes baseline comment density, TODO markers, error-handling absence, sleep, magic numbers, short names. |
| 7 | Polite annoyance detector | FULL | `analyzers/polite_annoyance.py` | Includes error suppression, defensive overcheck, apologetic comments, branching-entropy anomaly. |
| 8 | Hidden information | FULL | `analyzers/hidden_info.py` | None/global/raise documentation checks. |
| 9 | Deep module analysis | FULL | `analyzers/deep_module.py` | Cross-checks imported module attributes against functions/classes/globals. |
| 10 | Internal contradictions | FULL | `analyzers/contradictions.py` | Type contradictions, duplicate definitions, docstring contradictions, condition contradictions. |
| 11 | Pipeline integrity self-check | FULL | `pipeline_integrity.py`, pipeline startup | Checks `record_drift` and local analyzer execution wiring. |
| 12 | Unified report and integration | FULL | `models.Report`, `reporting.py`, `artifacts.py` | Console, JSON, SARIF, JUnit, Markdown, HTML. |
| 12a | CI exit code for high/critical | FULL | `cli.py --ci`, `Report.has_blocking_issues()` | Also supports explicit quality budgets. |
| 13 | Deterministic rule catalog | SUPERSET | `rules/catalog.py`, `analyzers/rule_catalog.py` | Rules are code, not prompt-only. |
| 14 | SARIF/JUnit/Markdown/HTML outputs | SUPERSET | `artifacts.py` | CI and human review surfaces. |
| 15 | Suppression governance | SUPERSET | `policy.py`, `docs/GOVERNANCE.md` | Owner/reason/expiry required. |
| 16 | Plugin API | SUPERSET | `plugins.py`, `docs/PLUGIN_API.md` | External deterministic rules can be loaded. |
| 17 | Baseline/new issue gating | SUPERSET | `policy.QualityGate` | `--baseline-report`, `--fail-on-new`, severity budgets. |
| 18 | Python data-flow-lite | SUPERSET | `python_dataflow.py` | Local taint-like source→sink detection. |
| 19 | Cross-file Python data-flow-lite | SUPERSET | `python_cross_file_dataflow.py` | Helper summaries across files. |
| 20 | JS/TS structure analyzer | SUPERSET | `javascript_structure.py` | Text/structure heuristics; full AST parser still future work. |
| 21 | Benchmark fixtures and metrics | SUPERSET | `benchmarks.py`, `docs/BENCHMARKS.md` | Built-in expectation metrics. |
| 22 | Parallel local scan | SUPERSET | `--workers`, `ThreadPoolExecutor` | AI and drift remain sequential by design. |
| 23 | Dependency resolver | SUPERSET | `type_resolution/dependencies.py`, `inspect-deps` | Reads Python/JS dependency manifests and lockfiles without importing project code. |
| 24 | SDK symbol index | SUPERSET | `type_resolution/sdk_index.py`, `index-sdk`, `--sdk-index-output` | Safe metadata mode by default; opt-in package imports for public symbols. |
| 25 | Pyright/Mypy adapters | SUPERSET | `type_resolution/type_tools.py`, `type-check`, `--type-tools` | Converts installed type-checker diagnostics into UnifiedReport. |
| 26 | Conservative SDK unknown-call validator | SUPERSET | `analyzers/unknown_calls.py`, `--unknown-call-check` | High-confidence missing public SDK attributes only; avoids runtime-object guesses. |

## Known limitations kept honest

- JS/TS analysis is still not a full AST parser.
- Python taint is lightweight and not a complete interprocedural security proof.
- Unknown-call detection is no longer text-only: v0.38 adds manifests, optional SDK indexing and pyright/mypy adapters; full confidence still requires real type checkers and installed stubs.
- v0.38 fixes dotted import alias resolution for SDK checks, including `import xml.etree.ElementTree as ET` and `import importlib.util` coexistence.
- Built-in benchmark is useful for regression but not a large real-world corpus.
