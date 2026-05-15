# AI Code Filter v45 — Variadic Binding Reference Wave

## Verified change

This wave extends the deterministic Python data-flow engine with limited, explicit variadic call binding:

- same-file wrappers forwarding `*args` into known shell/SQL/HTML sinks;
- same-file wrappers forwarding `**kwargs` into known shell/SQL/HTML sinks;
- cross-file imported wrappers forwarding `*args` into known sinks;
- cross-file imported wrappers forwarding `**kwargs` into known sinks.

This is intentionally not a claim of full Python call binding. Defaults, overloads, decorators, dynamic dispatch, runtime DI, and deep object graphs remain out of scope and are documented in `docs/LIMITATIONS.json`.

## Regression corpus

Added `tests/test_v45_variadic_call_binding.py` covering:

- same-file shell wrapper via forwarded `*args`;
- same-file shell wrapper via forwarded `**kwargs`;
- cross-file shell wrapper via forwarded `*args`;
- cross-file shell wrapper via forwarded `**kwargs`.

## Verification

- `compileall`: OK
- `pytest`: 296 passed, 7 known zipfile fixture warnings
- `analyze . --no-ai --no-drift --ci`: No problems found
- `truthfulness-gate . --ci`: No problems found
- `config-contract . --ci`: No problems found
- `rule-ownership . --ci`: No problems found
- `performance-budget --files 120 --max-seconds 8 --ci`: No problems found
- `release-audit . --ci`: No problems found
- `release-audit zip --ci`: No problems found
