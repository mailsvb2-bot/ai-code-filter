from __future__ import annotations

import json
from pathlib import Path
from typing import Any

LIMITATIONS: dict[str, Any] = {
    "engine": "deterministic static audit helper",
    "not_a_full_static_analyzer": True,
    "symbol_resolution": {
        "import_aliases": "supported",
        "from_import_aliases": "supported",
        "simple_assignment_aliases": "supported",
        "constructor_bound_method_aliases": "same-file simple assignments only",
        "dynamic_imports": "not_supported",
        "runtime_reflection": "limited",
        "database_backend_inventory": "supported for deterministic code/config/env surfaces",
    },
    "dataflow": {
        "local_assignments": "supported",
        "interprocedural_depth": 1,
        "same_file_helper_returns": "supported",
        "same_file_wrapper_sinks": "supported",
        "same_file_bound_method_wrapper_sinks": "supported for simple constructor aliases",
        "cross_file_taint": "limited",
        "type_inference": "basic",
        "project_call_graph": "lightweight static graph with unknown-call accounting",
        "database_consistency": "detects SQLite/Postgres/MySQL marker mismatches in runtime config, env contracts, and simple Python arrays/dicts; does not execute migrations or connect to databases",
    },
    "pytest_audit": {
        "run_pytest": "supported with explicit timeout",
        "summary_parsing": "pytest stdout/stderr summary heuristic",
        "masking_checks": ["skip/xfail without reason", "xpass", "import-only tests", "test without assertion", "broad exception swallowing"],
        "semantic_completeness": "heuristic signals, not proof",
        "coverage_audit": "coverage.py line/branch budget execution gate available as a separate command",
        "coverage_uncovered_files": "top uncovered measured files can be reported; not a semantic proof",
        "mutation_lite": "conservative mutation smoke gate available as a separate command",
        "limitations": ["does not prove semantic adequacy of assertions", "pytest plugin behavior depends on caller flags", "flaky-test diagnosis is not implemented"]
    },
    "coverage_audit": {
        "status": "coverage_execution_gate_not_behavior_proof",
        "supported": ["coverage.py run --branch over pytest", "line coverage budget", "branch coverage budget", "top uncovered measured files", "uncovered-file budget", "JSON/native report output"],
        "limitations": ["requires coverage.py installed", "coverage percentages do not prove assertions are meaningful", "flaky or environment-specific tests can still distort metrics"]
    },
    "mutation_audit": {
        "status": "mutation_testing_smoke_not_full_mutation_suite",
        "supported": ["temporary project copy", "boolean return flips", "comparison operator flips", "pytest execution per mutant", "surviving mutant findings", "mutation score budget"],
        "limitations": ["limited mutant operators", "equivalent mutants are possible", "large projects require explicit --max-mutants/timeout tuning"]
    },
    "behavior_audit": {
        "status": "explicit_contract_execution_not_proof",
        "supported": [
            "import probes executed in subprocesses with timeout",
            "function probes using JSON-serializable args/kwargs and expectations",
            "expected exception contracts",
            "command probes with exit-code/stdout/stderr expectations",
            "import-smoke probes for discovered production modules",
            "optional Python-probe socket blocking with --deny-network",
            "optional command-probe disable with --no-command-probes",
            "secret-like environment stripping with --deny-secret-env",
            "environment allowlist with --env-allowlist",
            "strict bundled sandbox policy with --strict-sandbox in the CLI"
        ],
        "limitations": [
            "does not infer business requirements automatically",
            "sandbox hardening is partial: --deny-network blocks Python socket creation but cannot fully confine arbitrary native subprocess behavior",
            "--strict-sandbox disables command probes and strips secret-like environment variables, but it is still a subprocess policy, not a kernel/container sandbox",
            "does not replace end-to-end integration tests, coverage.py, mutation testing, or real service/database verification",
            "import-smoke can execute import-time side effects, so use explicit specs for side-effectful projects"
        ]
    },
    "type_audit": {
        "status": "external_type_checker_bridge_plus_static_contract",
        "supported": ["pyright bridge when installed", "mypy bridge when installed", "type-ignore rationale check", "untyped public API budget", "Any leakage signal count"],
        "limitations": ["does not implement a complete type checker internally", "tool availability depends on environment", "static annotation heuristics can over/under-count dynamic APIs"]
    },
    "external_audit": {
        "status": "optional_external_sast_bridge",
        "supported": ["ruff", "bandit", "semgrep", "pip-audit"],
        "limitations": ["external tools must be installed", "outputs are summarized and normalized, not fully reinterpreted"]
    },
    "deployment_audit": {
        "status": "static_deployment_contract_smell_audit",
        "supported": ["Dockerfile", "docker compose", "GitHub Actions", "systemd", "nginx proxy config"],
        "limitations": ["does not deploy or contact live infrastructure", "cannot verify provider firewall/DNS/TLS state"]
    },
    "migration_audit": {
        "status": "static_migration_lifecycle_smell_audit",
        "supported": ["migration presence when DB config exists", "duplicate revision hints", "destructive SQL hints", "SQLite/Postgres mixed semantics"],
        "limitations": ["does not connect to DB", "does not execute migrations", "does not prove schema equivalence"]
    },
    "supply_chain_audit": {
        "status": "manifest_supply_chain_smell_audit",
        "supported": ["requirements", "pyproject", "package.json", "unpinned/broad/direct-url dependency hints"],
        "limitations": ["does not query vulnerability databases unless external pip-audit bridge is installed", "does not prove package provenance"]
    },
    "framework_semantics": ["generic", "flask-lite", "javascript-lite", "messaging-bot-lite", "autonomy-canon-lite"],
    "execution_safety": {
        "default_mode": "static analyzers avoid executing audited code; behavior/coverage/mutation probes are explicit execution gates",
        "recommended_untrusted_repo_policy": "Use static analyze/release-audit first. Run behavior-audit only with --strict-sandbox inside an OS/container sandbox for untrusted projects.",
        "not_guaranteed": "No in-process Python sandbox can safely contain hostile code."
    },
    "production_claim": "Use as a CI helper. Do not treat TOTAL=0, internal scorecard 100/100, or skipped optional tools as proof of production readiness.",
}


def limitation_registry() -> dict[str, Any]:
    return dict(LIMITATIONS)


def write_limitations(path: str | Path | None) -> None:
    """Write registry JSON when a path is provided; return None when omitted."""
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(limitation_registry(), ensure_ascii=False, indent=2), encoding="utf-8")
