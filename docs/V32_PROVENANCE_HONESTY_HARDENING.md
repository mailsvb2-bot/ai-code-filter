<!-- ai-code-filter-historical-versions: true -->
# v0.38.0 Provenance honesty hardening

This release strengthens audit/fix provenance validation so reports distinguish:

- tool-detected findings,
- release-audit findings,
- external adversarial audit findings,
- human review findings,
- regression-fixture hardening gaps.

The validator now checks schema version, item containers, count fields, item IDs, source evidence, command structure, reviewer identity, version boundaries, tool version metadata, wording conflicts and regression-evidence requirements.
