<!-- ai-code-filter-historical-versions: true -->
# Encoded Separator / Manifest Collision / Structured Duplicate Hardening v0.38

This suite makes the v0.38 external-audit findings permanent acceptance checks.
It verifies that release/integrity validators reject encoded and double-encoded
path separators, manifest generation collisions, encoded Markdown targets,
encoded zip members, and duplicate keys in structured configuration formats.

## Commands

```bash
ai-code-filter encoded-collision-hardening-suite --ci --output encoded_collision.json
ai-code-filter encoded-collision-hardening-suite --summary-json encoded_collision_summary.json
ai-code-filter release-audit ai_code_filter_refactored_v38.zip \
  --adversarial-suite \
  --blindspot-suite \
  --path-portability-suite \
  --structured-hardening-suite \
  --encoded-collision-hardening-suite \
  --ci
```

## Threat classes

- percent-encoded and double-encoded `/` and `\\` inside path components;
- case-insensitive and Unicode-normalized manifest collisions;
- manifest generation consistency for the same collision rules;
- encoded Markdown link targets;
- encoded zip member names;
- YAML-like and INI/CFG duplicate key/section hardening;
- false-positive guard for repeated YAML keys across separate list items.
