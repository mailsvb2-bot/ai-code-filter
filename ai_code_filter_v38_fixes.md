# v38 fixes/additions

- **V38-001** — Unified capability registry added: Capability metadata was scattered across rules, coverage and suite modules.
- **V38-002** — Property-style fuzz suite added: Manual fixtures alone do not explore encoded/path ambiguity families.
- **V38-003** — Architecture mass audit added: Suite growth needed a guard against architecture sprawl and oversized modules.
- **V38-004** — Dependency audit added: Dependency manifests lacked a focused consistency audit command.
- **V38-005** — Release audit can invoke new governance layers: The release command did not expose fuzz, mass, dependency and capability registry checks.
