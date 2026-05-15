<!-- ai-code-filter-historical-versions: true -->
# Claim Evidence Contract v0.38

This layer verifies that audit/fix reports do not only state provenance, but also attach enough evidence to trust each claim.

It checks:

- document-level `claim_summary.by_source` totals;
- non-empty `verification_commands` with coherent `status`/`exit_code`;
- item-level `evidence_type`;
- tool-origin findings backed by command output or artifact reports;
- external-origin findings backed by reviewer identity and review date;
- reproduced defects with reproduction command, observed-before and verified-after fields;
- regression claims with test paths;
- blind spots/hardening gaps with a threat-model gap explanation.

Commands:

```bash
ai-code-filter validate-claim-evidence fixes.json --ci
ai-code-filter claim-evidence-contract-suite --ci
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --claim-evidence-contract-suite --ci
```
