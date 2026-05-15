# Claim Summary Verification Acceptance

This layer makes the provenance/evidence report contract stricter around document-level summaries and verification commands.

It validates that:

- `claim_summary.by_source` uses supported source methods and strict integer counts;
- `claim_summary.total_count` exists and matches the item count;
- `verification_commands` are unique and status/exit codes are coherent;
- skipped commands have `exit_code=0` and a `skip_reason`;
- tool and suite-origin claims include a semantic `tool_version`;
- review dates are real calendar dates;
- `before_version`/`after_version` boundaries increase;
- valid reports are not rejected by the hardening suite.

Commands:

```bash
ai-code-filter claim-summary-verification-suite --ci
ai-code-filter release-audit dist.zip --claim-summary-verification-suite --ci
```
