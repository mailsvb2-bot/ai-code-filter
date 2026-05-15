<!-- ai-code-filter-historical-versions: true -->
# Mass and Dependency Audit v0.38

`mass-audit` checks architecture mass and suite-sprawl risks. `dependency-audit` checks dependency declaration consistency and keeps optional AI dependencies out of the mandatory install path.

```bash
ai-code-filter mass-audit . --strict --ci
ai-code-filter dependency-audit . --ci
```
