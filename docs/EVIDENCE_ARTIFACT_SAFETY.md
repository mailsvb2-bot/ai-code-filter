<!-- ai-code-filter-historical-versions: true -->
# Evidence Artifact Safety v0.38

AI Code Filter v0.38 adds an evidence/artifact safety layer for audit and fixes reports. It verifies that evidence paths, verification artifacts, test paths, commands, reviewer identities, review dates, version boundaries and fixes statuses are safe and reproducible.

## Commands

```bash
ai-code-filter evidence-artifact-safety-suite --ci --output evidence_artifact_safety.json
ai-code-filter validate-evidence-artifact-safety fixes.json --ci
ai-code-filter release-audit ai_code_filter_refactored_v38.zip --evidence-artifact-safety-suite --ci
```

## Covered classes

- traversal, absolute, Windows-drive, URL and control-character evidence references
- traversal, absolute, Windows-drive, URL and control-character verification artifacts
- duplicate evidence entries and duplicate verification artifact references
- newline and shell-control tokens in verification commands
- duplicate commands after whitespace normalization
- placeholder or non-normalized reviewer identities
- future review dates
- unsafe or non-Python regression test paths
- leading-zero and unrealistic semver boundaries
- fixes reports that still contain non-final item statuses
- policy gaps without `threat_model_gap`

This layer complements provenance and claim-evidence validation: provenance says who/what found a claim; claim evidence says which evidence fields exist; evidence artifact safety checks that those fields are safe and not misleading.
