<!-- ai-code-filter-historical-versions: true -->
# Assistant capability layer

Version: 0.38.0

This layer adds deterministic assistant-style helpers without claiming hidden or
network-only abilities. The package can now turn scan outputs into review plans,
patch queues, evidence ledgers, prompt packs, and capability matrices.

## Commands

```bash
ai-code-filter assistant-capabilities --output capabilities.json
ai-code-filter explain-report report.json --output review.md
ai-code-filter explain-report report.json --json --output review.json
ai-code-filter review-plan report.json --output closure-map.json
ai-code-filter patch-plan report.json --output patch-plan.json
ai-code-filter prompt-pack --output prompts.json
```

## Boundaries

- No hidden reasoning is exported.
- No network access is performed by these helpers.
- No source file is rewritten automatically.
- Optional external evidence must be passed in by connectors or humans.
- Skipped tools remain explicit risk, not success.

## Purpose

The assistant layer gives maintainers the same type of structured output expected
from a careful reviewer: P0/P1/P2 queues, risks, stop conditions, and validation
commands. All of it is derived from the native report and explicit metadata.
