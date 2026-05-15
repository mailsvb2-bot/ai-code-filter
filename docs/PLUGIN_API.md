# Plugin API

A plugin is a Python file passed with `--plugin path/to/plugin.py`. It must expose `register_rules()` and return a list of `Rule` objects.

```python
from ai_code_filter.models import Issue, Severity
from ai_code_filter.rules.catalog import Rule


def register_rules():
    def check(payload, tree):
        if "BANME" in payload.content:
            return [Issue(
                file=payload.relative_path,
                category="PL001: Plugin",
                severity=Severity.HIGH,
                detector="rule_catalog",
                description="Plugin marker found.",
                recommendation="Remove marker.",
                line_number=1,
                location="BANME",
            )]
        return []

    return [Rule("PL001", "Plugin marker", Severity.HIGH, "text", "Plugin", check)]
```

The core loads plugins into the same `RuleCatalog`; duplicate rule ids are rejected.
