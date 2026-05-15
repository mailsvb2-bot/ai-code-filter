<!-- ai-code-filter-historical-versions: true -->
# Structured / Unicode Hardening Acceptance v0.38

This layer keeps regression fixtures for structured-file and Unicode/path-confusable defects that can bypass ordinary release checks.
It covers:

- Unicode slash confusables: fullwidth slash, division slash, fraction slash
- Home-directory shorthand paths (`~/...`)
- Superscript Windows device names such as `COM¹.txt`
- Unicode-normalized filename collisions
- Duplicate JSON keys
- XML `DOCTYPE` / `ENTITY` declarations
- Markdown embedded HTML `href` / `src` targets
- Unsafe or duplicate zip directory entries
- OS-generated release trash files such as `.DS_Store`, `Thumbs.db`, `desktop.ini`

Run directly:

```bash
ai-code-filter structured-hardening-suite --ci --output structured_hardening.json
ai-code-filter structured-hardening-suite --summary-json structured_hardening_summary.json
```

Run as part of release acceptance:

```bash
ai-code-filter release-audit ai_code_filter_refactored_v38.zip \
  --adversarial-suite \
  --blindspot-suite \
  --path-portability-suite \
  --structured-hardening-suite \
  --ci
```
