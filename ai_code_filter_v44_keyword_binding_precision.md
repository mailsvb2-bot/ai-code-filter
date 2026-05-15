# AI Code Filter v44 — Keyword Binding Precision

## Implemented

- Added explicit keyword-argument binding for summarized same-file wrappers.
- Added explicit keyword-argument binding for summarized cross-file wrappers.
- Added cross-file helper return flow into direct SQL/shell/HTML sinks.
- Added regression tests for same-file shell wrapper keyword calls, cross-file shell wrapper keyword calls, and cross-file pass-through helper keyword calls.

## Honest limitation

This is still a deterministic static audit helper. It supports positional and explicit keyword binding for summarized functions, but it does not implement full Python call binding for `*args`, `**kwargs`, dynamic dispatch, dependency injection, or runtime reflection.
