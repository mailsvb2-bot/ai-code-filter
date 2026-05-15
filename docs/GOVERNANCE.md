# Governance model

AI Code Filter has two gates:

1. **Deterministic rules** produce stable findings with rule ids.
2. **Quality gates** decide whether a build fails.

Recommended CI command:

```bash
ai-code-filter analyze . --no-ai --ci \
  --output ai-code-filter.json \
  --sarif ai-code-filter.sarif \
  --junit ai-code-filter.xml \
  --markdown ai-code-filter.md \
  --max-critical 0 \
  --max-high 0 \
  --baseline-report .ai-code-filter/baseline.json \
  --fail-on-new HIGH
```

Suppressions must be explicit, owned and expiring. Example:

```json
{
  "suppressions": [
    {
      "rule_id": "PY020",
      "file": "legacy/report.py",
      "owner": "platform-team",
      "reason": "Legacy Python 3.8 compatibility; removal tracked in ARCH-42",
      "expires": "2026-12-31"
    }
  ]
}
```

A suppression without owner, reason or valid expiry is reported as a HIGH governance problem.
