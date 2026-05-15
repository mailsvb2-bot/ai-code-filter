# Production-readiness boundary

AI Code Filter is production-useful as a local/CI audit helper when its deterministic gates are configured explicitly. It is not an enterprise security platform by itself and it must not present internal success metrics as external certification.

## Release blocker policy

A release should be blocked when any of these are true:

- CRITICAL/HIGH findings are present without reviewed suppression governance.
- Failed files exist in the native report.
- Optional tools are skipped but the release claim says they ran.
- Behavior/coverage/mutation gates are claimed while their commands were not executed.
- `TOTAL=0` or scorecard `100/100` is used as proof of production readiness rather than scoped gate evidence.

## Trusted versus untrusted repositories

Static commands can inspect untrusted source text. Execution gates run code and must be isolated by the caller.

Recommended untrusted order:

```bash
ai-code-filter analyze . --no-ai --no-drift --ci
ai-code-filter release-audit artifact.zip --ci
```

Recommended behavior-audit minimum for trusted or externally sandboxed projects:

```bash
ai-code-filter behavior-audit . --spec behavior.json --strict-sandbox --ci
```

`--strict-sandbox` disables command probes, strips secret-like environment variables and blocks Python socket creation inside Python probes. It does not replace containers, seccomp, VMs, firewalls or CI runner isolation.

## Evidence wording

Use precise wording:

- Good: “The configured deterministic gates passed on this commit.”
- Bad: “The project is proven production-ready.”
- Good: “Semgrep was skipped because it was not installed.”
- Bad: “External SAST passed.”
