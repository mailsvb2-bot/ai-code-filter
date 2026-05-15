# v43 Cross-file precision hardening

## Implemented

- Cross-file Python data-flow now canonicalizes imported aliases while summarizing wrapper sinks.
- Cross-file shell wrappers using `from subprocess import run` are detected when imported under an alias.
- Simple imported class constructor aliases are resolved for bound-method calls, for example `runner = Runner(); runner.execute(cmd)`.
- `Runner.execute(...)`-style bound methods are no longer treated as SQL sinks solely because the method name is `execute`.
- Cross-file findings now carry high-confidence metadata and evidence fields.

## Regression coverage

- `tests/test_v43_cross_file_precision.py::test_cross_file_shell_wrapper_import_alias_is_detected`
- `tests/test_v43_cross_file_precision.py::test_cross_file_bound_method_shell_wrapper_is_detected_without_sql_false_positive`
- `tests/test_v43_cross_file_precision.py::test_symbol_table_resolves_imported_constructor_bound_method_alias`

## Honest limitations

This remains deterministic lite analysis, not a full interprocedural type/taint engine. Dynamic imports, runtime reflection, dependency-injected constructors, inheritance dispatch, and deep cross-file object graphs remain out of scope unless represented by explicit summaries/rules.
