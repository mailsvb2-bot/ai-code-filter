<!-- ai-code-filter-historical-versions: true -->
# Unified Capability Registry v0.38

v0.38 introduces a single capability registry for deterministic rules, analyzer capabilities and acceptance suites. The registry records `capability_id`, domain, detector, lifecycle status, version introduced and regression-test evidence.

Commands:

```bash
ai-code-filter capability-registry --validate --ci
ai-code-filter capability-registry --json capability_registry.json
```

The registry prevents future growth from becoming a set of disconnected suite modules without ownership metadata.
