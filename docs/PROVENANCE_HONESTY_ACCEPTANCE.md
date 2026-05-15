<!-- ai-code-filter-historical-versions: true -->
# Audit Provenance / Claim Honesty Acceptance v0.38

This suite prevents a release note, fixes file, or assistant-style report from conflating different discovery sources.
It separates:

- findings detected by the tool itself;
- findings discovered by external/adversarial review;
- blind spots converted into regression fixtures;
- hypotheses or hardening gaps.

## CLI

```bash
ai-code-filter provenance-honesty-suite --ci --output provenance_honesty.json
ai-code-filter provenance-honesty-suite --summary-json provenance_honesty_summary.json
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --provenance-honesty-suite --ci
```

## Contract

Machine-readable fixes/findings documents should include:

- `artifact_kind`;
- document-level `audit_provenance.claim_boundary`;
- exact `fixed_count`/item count consistency;
- per-item `source.method`;
- reproducible evidence or command;
- `classification` and `status`;
- `before_version` and `after_version`;
- `regression_test=true` for blind spots and hardening gaps.

The goal is not to prove every fix correct. The goal is to prevent misleading claims such as “the tool found 27 errors” when the items came from an external adversarial audit and were later converted into regression tests.
