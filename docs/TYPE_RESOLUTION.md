<!-- ai-code-filter-historical-versions: true -->
# Type resolution and external SDK knowledge

AI Code Filter v0.38 adds a conservative type-resolution layer. Its purpose is to reduce false "hallucinated call" findings by checking local code, dependency manifests, optional SDK symbol indexes, and external type-checker output.

## Components

- `DependencyResolver` reads `pyproject.toml`, requirements files, `package.json`, and lockfiles without importing project code.
- `SDKIndex` records available Python import roots. In safe mode it uses `importlib.util.find_spec`. In opt-in mode it imports package roots and records public attributes, callables, and class methods.
- `TypeToolAdapter` runs installed `pyright --outputjson` and `mypy` and maps diagnostics into `UnifiedReport` issues.
- `UnknownCallValidator` performs conservative SDK attribute checks only when enabled. It avoids general runtime-object method claims because those require a full type checker.

## Safety boundary

SDK imports are disabled by default. Enable them only in trusted environments:

```bash
ai-code-filter index-sdk . --output .ai-code-filter/sdk-index.json --import-packages
ai-code-filter analyze . --no-ai --sdk-index --unknown-call-check --sdk-index-output .ai-code-filter/sdk-index.json
```

## Type checker bridge

```bash
ai-code-filter type-check . --output type-report.json --sarif type-report.sarif --ci
```

The adapter does not install `pyright` or `mypy`. If they are missing, it returns no blocking issues. Install them in CI when type checking is required.

## What is still not claimed

This is not a full Python type checker. Full confidence still requires Pyright/Mypy/TypeScript, installed dependencies, stubs, and framework-specific models.


## v0.38 fix

Unknown-call validation now indexes full dotted import modules such as `xml.etree.ElementTree` instead of only the top-level root `xml`. This avoids false HIGH findings for aliases like `import xml.etree.ElementTree as ET`.
