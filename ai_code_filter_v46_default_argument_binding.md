# v46 default argument binding

This wave adds deterministic default-argument taint propagation for summarized Python helpers and wrappers.

Covered examples:

- same-file shell wrapper with tainted default argument;
- same-file pass-through helper default flowing into a shell sink;
- cross-file shell wrapper with tainted default argument;
- cross-file pass-through helper default flowing into a shell sink.

This remains intentionally limited: it does not claim full Python call binding, decorator-aware signature rewriting, overload resolution, runtime DI, or deep object graph inference.
