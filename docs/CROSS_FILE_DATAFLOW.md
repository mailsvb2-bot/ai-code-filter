# Cross-file Python data-flow lite

`PythonCrossFileDataFlowAnalyzer` builds small summaries for sibling Python modules and checks imported helper calls.

It currently models:

- source helpers returning request/input/environment values;
- sink wrappers around SQL `execute` / `executemany`;
- sink wrappers around shell execution with `os.system` or `subprocess.*(..., shell=True)`;
- sink wrappers around raw template/HTML functions;
- sanitizer calls such as `html.escape`, `markupsafe.escape`, `shlex.quote`, and URL quoting.

The analyzer is intentionally conservative. It is not a full interprocedural static-analysis engine. It reports only short, explainable source-to-sink paths across local project modules.

Capability IDs:

- `PYXDF001` — cross-file SQL injection path;
- `PYXDF002` — cross-file command injection path;
- `PYXDF003` — cross-file raw HTML/template path.

Known limits:

- no dynamic import resolution;
- no framework-specific router graph yet;
- no alias analysis beyond simple imports and `from x import y`;
- no class instance field taint propagation;
- no database-driver-specific prepared-statement validation beyond avoiding direct tainted query strings.
