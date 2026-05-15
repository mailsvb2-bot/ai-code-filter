# v0.59 GitHub/corpus/sandbox/PR-mode expansion

This release adds first-class surfaces for:

1. GitHub Actions annotations and PR comment Markdown (`github-integration`).
2. Semgrep/Bandit/Ruff/Pyright normalization packs (`normalization-packs`).
3. 20-project real-world corpus manifest (`real-world-corpus`).
4. Recall/precision proxy benchmark reports (`precision-recall-report`).
5. GitHub Code Scanning SARIF readiness audit (`sarif-github-audit`).
6. Trend dashboard HTML (`dashboard`).
7. Deeper framework profiles (`framework-profile-audit`).
8. Trusted custom policy-pack plugin API (`plugin-api-audit`).
9. Optional Docker sandbox command generation (`docker-sandbox`).
10. Incremental PR mode with call-graph neighborhood (`incremental-pr`).

Security boundary: plugin packs and behavior probes remain trusted-only unless run inside an external sandbox. The Docker command generator does not silently execute Docker.
