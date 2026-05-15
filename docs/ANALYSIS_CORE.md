<!-- ai-code-filter-historical-versions: true -->
# Analysis Core v0.38

This release improves the deterministic core without pretending to be a complete static-analysis engine.

## Python data-flow-lite

The Python pass now supports:

- direct request/input/env sources;
- derived taint through assignment, f-strings, concatenation and containers;
- simple same-file helper return summaries;
- parameter-return helper summaries such as `identity(x) -> x`;
- common sanitizer calls such as `html.escape`, `markupsafe.escape`, `shlex.quote` and URL quoting;
- SQL, shell and raw-template sinks.

Boundaries:

- no cross-file call graph;
- no class-aware dynamic dispatch;
- no type-aware framework modeling;
- no guarantee of complete taint coverage.

## JavaScript/TypeScript structure fallback

The JS/TS pass now detects:

- wildcard `postMessage` target origins;
- message listeners without nearby origin allow-list checks;
- URL parameter redirects through `location`;
- string-based `setTimeout`/`setInterval` execution;
- URL parameter `window.open` sinks;
- `document.domain` relaxation;
- browser-controlled values flowing to raw HTML DOM sinks.

Boundaries:

- no full ECMAScript AST;
- no bundler/module resolution;
- no framework-specific sanitizer model;
- findings are high-signal heuristics, not proof of exploitability.

## Parallel local scan

`--workers N` parallelizes deterministic local analyzers. AI review and drift remain sequential so external side effects stay predictable.
