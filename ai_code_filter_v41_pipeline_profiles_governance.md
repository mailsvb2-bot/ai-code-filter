# AI Code Filter v41 — Pipeline/Profile/Governance Hardening

Implemented in this wave:

- Project-specific profile analyzer with `messaging-bot` and `autonomy-canon` profiles.
- Strict suppression governance: `reason`, `owner`, and `expires` are mandatory; expired and unused suppressions are reported.
- Baseline contract audit command for stale/growing/missing-file baselines.
- Rule ownership registry and validation command.
- SARIF quality upgrade with stable fingerprints, confidence, and evidence properties.
- Runtime config profile propagation through the existing AnalysisPipeline without introducing a second decision core.

Honest limitations remain in `docs/LIMITATIONS.json`: this is still a deterministic audit engine, not a complete static analyzer.
