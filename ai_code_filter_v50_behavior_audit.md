# v50 Behavior Audit

Added `behavior-audit` for explicit production behavior contract execution.

Supported probes:

- import probes;
- function probes with JSON args/kwargs;
- expected exception contracts;
- command probes with exit-code/stdout/stderr expectations;
- import-smoke probes for discovered production modules.

This is a behavioral CI smoke layer, not proof of full production correctness.
