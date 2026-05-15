# Benchmarks

Run:

```bash
python ai_filter.py benchmark --output benchmark.json --ci
```

The built-in benchmark checks selected positive and negative expectations for deterministic rules,
Python data-flow-lite, and JavaScript structure checks.

Metrics are expectation-level metrics, not a claim of real-world precision. A production release must
add real repository fixtures and track false-positive / false-negative deltas over time.
