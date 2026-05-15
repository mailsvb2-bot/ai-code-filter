from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import DEFAULT_EXTENSIONS, DEFAULT_MODEL, RuntimeConfig
from .pipeline import AnalysisPipeline
from .coverage import coverage_matrix, write_coverage_matrix
from .models import Issue, Severity
from .policy import issue_fingerprint
from .finding_core import FindingCore, FindingPolicy
from .artifacts import write_html_report, write_junit_report, write_markdown_report, write_sarif_report
from .reporting import print_report, write_json_report
from .rules import build_default_catalog
from .benchmarks import write_benchmark_report
from .type_resolution.dependencies import DependencyResolver
from .type_resolution.sdk_index import build_sdk_index, write_sdk_index
from .type_resolution.type_tools import TypeToolAdapter
from .assistant.capabilities import assistant_capability_matrix
from .assistant.patch_plan import build_patch_plan
from .assistant.prompt_packs import prompt_pack
from .assistant.report_explainer import explain_report
from .assistant.report_io import load_native_report, write_json, write_text
from .assistant.review_plan import build_review_plan
from .release.audit import audit_release, _copy_or_extract
from .integrity import write_manifest, verify_manifest
from .adversarial import adversarial_suite_summary, run_adversarial_suite
from .blindspots import blindspot_suite_summary, run_blindspot_suite
from .path_portability import path_portability_suite_summary, run_path_portability_suite
from .structured_hardening import structured_hardening_suite_summary, run_structured_hardening_suite
from .encoded_collision_hardening import encoded_collision_hardening_suite_summary, run_encoded_collision_hardening_suite
from .provenance_honesty import provenance_honesty_suite_summary, run_provenance_honesty_suite, validate_provenance_file
from .claim_evidence_contract import claim_evidence_contract_suite_summary, run_claim_evidence_contract_suite, validate_claim_evidence_file
from .claim_summary_verification import claim_summary_verification_suite_summary, run_claim_summary_verification_suite
from .evidence_artifact_safety import evidence_artifact_safety_suite_summary, run_evidence_artifact_safety_suite, validate_evidence_artifact_safety_file
from .array_ambiguity import array_ambiguity_suite_summary, run_array_ambiguity_suite
from .capabilities.registry import capability_registry_summary, validate_capability_registry
from .fuzzing import fuzz_suite_summary, run_fuzz_suite
from .mass_audit import mass_audit_summary, run_mass_audit
from .dependency_audit import dependency_audit_summary, run_dependency_audit
from .limitations import limitation_registry, write_limitations
from .config_contract import audit_config_contract
from .db_consistency import audit_db_consistency
from .truthfulness import run_truthfulness_gate, validate_limitations_file
from .profiles import normalize_profiles
from .baseline_contract import audit_baseline
from .rule_ownership import audit_rule_ownership, write_default_registry
from .performance_budget import run_performance_budget
from .fix_suggestions import build_fix_suggestions_from_file
from .pytest_audit import audit_pytest, write_pytest_summary
from .behavior_audit import audit_behavior, write_behavior_summary
from .coverage_audit import audit_coverage, write_coverage_summary
from .mutation_audit import audit_mutation_lite, write_mutation_summary
from .project_call_graph import build_project_call_graph, write_call_graph, audit_call_graph
from .type_audit import audit_type_intelligence, write_type_audit_summary
from .external_audit import audit_external_tools, write_external_audit_summary
from .deployment_audit import audit_deployment, write_deployment_summary
from .migration_audit import audit_migrations, write_migration_summary
from .supply_chain_audit import audit_supply_chain, write_supply_chain_summary
from .precision_audit import audit_precision_corpus, write_precision_summary
from .stress_audit import audit_stress, write_stress_summary
from .quality_matrix import audit_quality_matrix, write_quality_matrix_summary
from .rule_quality import audit_rule_quality, write_rule_quality_summary
from .golden_fixtures import audit_golden_fixtures, write_golden_fixture_summary
from .external_normalization import normalize_external_findings, write_external_normalization_summary
from .zip_fixture_audit import audit_zip_fixtures, write_zip_fixture_summary
from .compatibility_audit import audit_compatibility, write_compatibility_summary
from .ownership_conflicts import audit_ownership_conflicts, write_ownership_conflict_summary
from .grep_audit import audit_grep_patterns, write_grep_audit_summary
from .policy_as_code import audit_policy_as_code, write_policy_summary
from .ci_profiles import audit_ci_profiles, write_ci_profile_summary

from .github_integration import write_github_outputs
from .normalization_packs import list_packs, normalize_with_pack, write_pack_summary
from .real_world_corpus import write_default_corpus, audit_corpus_manifest
from .precision_recall import benchmark_precision_recall, write_precision_recall_summary
from .sarif_github import audit_github_sarif
from .dashboard import write_trend_dashboard
from .framework_profile_audit import audit_framework_profiles
from .plugin_api import validate_plugin_manifest
from .docker_sandbox import build_behavior_sandbox_command, write_docker_sandbox_summary
from .incremental_pr import audit_incremental_pr, write_incremental_pr_summary
from .release_evidence import audit_release_evidence, write_release_evidence_summary
from .changed_files_audit import audit_changed_files, write_changed_files_summary
from .scorecard import audit_scorecard, write_scorecard_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI Code Filter — layered code auditor")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze project or files")
    analyze.add_argument("paths", nargs="+")
    analyze.add_argument("--model", default=DEFAULT_MODEL)
    analyze.add_argument("--output", "-o", help="Write native JSON report")
    analyze.add_argument("--sarif", help="Write SARIF 2.1.0 report for code scanning")
    analyze.add_argument("--junit", help="Write JUnit XML report for CI systems")
    analyze.add_argument("--markdown", help="Write Markdown report")
    analyze.add_argument("--html", help="Write standalone HTML report")
    analyze.add_argument("--extensions", nargs="+", default=list(DEFAULT_EXTENSIONS))
    analyze.add_argument("--ci", action="store_true")
    analyze.add_argument("--no-ai", action="store_true", help="Run deterministic local analyzers only")
    analyze.add_argument("--no-drift", action="store_true", help="Do not update or read drift history during analyze")

    analyze.add_argument("--plugin", action="append", default=[], help="Load extra deterministic rules from a plugin file exposing register_rules()")
    analyze.add_argument("--suppressions", help="JSON suppression file with owner/reason/expiry governance")
    analyze.add_argument("--baseline-report", help="Previous native JSON report for new-issue gating")
    analyze.add_argument("--fail-on-new", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Fail CI on new issues at or above this severity")
    analyze.add_argument("--max-critical", type=int, help="Maximum allowed CRITICAL issues")
    analyze.add_argument("--max-high", type=int, help="Maximum allowed HIGH issues")
    analyze.add_argument("--max-medium", type=int, help="Maximum allowed MEDIUM issues")
    analyze.add_argument("--max-low", type=int, help="Maximum allowed LOW issues")
    analyze.add_argument("--print-fingerprints", action="store_true", help="Print stable issue fingerprints for baselines/suppressions")
    analyze.add_argument("--write-baseline", help="Write current native JSON report as a reviewable baseline")
    analyze.add_argument("--print-limitations", action="store_true", help="Print the machine-readable analysis limitations registry")
    analyze.add_argument("--workers", type=int, default=1, help="Parallel local analyzer workers. AI review and drift remain sequential.")
    analyze.add_argument("--type-tools", action="store_true", help="Run optional external type-checker adapters when installed: pyright and mypy.")
    analyze.add_argument("--sdk-index", action="store_true", help="Build a safe SDK/dependency index using manifests and module availability checks; does not import packages by default.")
    analyze.add_argument("--import-packages", action="store_true", help="Opt in to importing trusted external/stdlib package roots for public symbol indexing. Use only in trusted environments.")
    analyze.add_argument("--sdk-index-output", help="Write SDK/dependency index JSON to this path.")
    analyze.add_argument("--unknown-call-check", action="store_true", help="Enable conservative unknown external SDK attribute validation.")
    analyze.add_argument("--profile", action="append", choices=["generic", "messaging-bot", "autonomy-canon", "fastapi", "flask", "django", "sqlalchemy"], help="Enable project-specific deterministic checks; can be passed multiple times.")


    call_graph = sub.add_parser("call-graph", help="Build a project call graph with unknown-call accounting")
    call_graph.add_argument("paths", nargs="+", help="Project path(s) to index")
    call_graph.add_argument("--output", "-o", required=True, help="Write call graph JSON")
    call_graph.add_argument("--extensions", nargs="+", default=[".py"], help="Extensions to include; Python only is indexed")
    call_graph.add_argument("--max-files", type=int, default=10000, help="Maximum Python files to index before marking graph truncated")
    call_graph.add_argument("--max-depth", type=int, default=4, help="Reserved path-rendering depth for downstream tools")
    call_graph.add_argument("--max-unknown-ratio", type=float, help="Fail CI if unknown/dynamic call ratio exceeds this budget")
    call_graph.add_argument("--ci", action="store_true")
    call_graph.add_argument("--report", help="Write native JSON report for call-graph governance findings")

    baseline = sub.add_parser("baseline", help="Compare current contracts with baseline")
    baseline.add_argument("paths", nargs="+")
    baseline.add_argument("--baseline", required=True)
    baseline.add_argument("--extensions", nargs="+", default=list(DEFAULT_EXTENSIONS))
    baseline.add_argument("--output", "-o", help="Write native JSON report")
    baseline.add_argument("--sarif", help="Write SARIF 2.1.0 report for code scanning")
    baseline.add_argument("--junit", help="Write JUnit XML report for CI systems")
    baseline.add_argument("--markdown", help="Write Markdown report")
    baseline.add_argument("--html", help="Write standalone HTML report")
    baseline.add_argument("--ci", action="store_true")

    baseline.add_argument("--max-critical", type=int)
    baseline.add_argument("--max-high", type=int)
    baseline.add_argument("--max-medium", type=int)
    baseline.add_argument("--max-low", type=int)

    baseline_audit = sub.add_parser("baseline-audit", help="Audit a native JSON baseline contract")
    baseline_audit.add_argument("baseline")
    baseline_audit.add_argument("--project-root", help="Project root used to verify baseline file references")
    baseline_audit.add_argument("--max-age-days", type=int, default=90)
    baseline_audit.add_argument("--max-issues", type=int)
    baseline_audit.add_argument("--output", "-o", help="Write native JSON report")
    baseline_audit.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    baseline_audit.add_argument("--junit", help="Write JUnit XML report")
    baseline_audit.add_argument("--markdown", help="Write Markdown report")
    baseline_audit.add_argument("--html", help="Write standalone HTML report")
    baseline_audit.add_argument("--ci", action="store_true")

    ownership = sub.add_parser("rule-ownership", help="Validate or generate the rule ownership registry")
    ownership.add_argument("project", nargs="?", default=".")
    ownership.add_argument("--registry", help="Registry path; defaults to docs/RULE_OWNERSHIP.json in project")
    ownership.add_argument("--write-default", action="store_true", help="Write a default registry before validating")
    ownership.add_argument("--output", "-o", help="Write native JSON report")
    ownership.add_argument("--ci", action="store_true")

    drift = sub.add_parser("drift-check", help="Update and check drift history")
    drift.add_argument("project")
    drift.add_argument("--extensions", nargs="+", default=list(DEFAULT_EXTENSIONS))
    drift.add_argument("--output", "-o", help="Write native JSON report")
    drift.add_argument("--sarif", help="Write SARIF 2.1.0 report for code scanning")
    drift.add_argument("--junit", help="Write JUnit XML report for CI systems")
    drift.add_argument("--markdown", help="Write Markdown report")
    drift.add_argument("--html", help="Write standalone HTML report")
    drift.add_argument("--ci", action="store_true")

    drift.add_argument("--max-critical", type=int)
    drift.add_argument("--max-high", type=int)
    drift.add_argument("--max-medium", type=int)
    drift.add_argument("--max-low", type=int)

    deps = sub.add_parser("inspect-deps", help="Inspect dependency manifests without importing SDKs")
    deps.add_argument("project")
    deps.add_argument("--output", "-o", help="Write dependency manifest JSON")

    sdk = sub.add_parser("index-sdk", help="Build optional SDK symbol index from dependency manifests and imports")
    sdk.add_argument("project")
    sdk.add_argument("--output", "-o", required=True, help="Write SDK index JSON")
    sdk.add_argument("--import-packages", action="store_true", help="Import dependency roots to collect public symbols. Use only in trusted environments.")

    typecheck = sub.add_parser("type-check", help="Run optional pyright/mypy adapters when installed")
    typecheck.add_argument("project")
    typecheck.add_argument("--output", "-o", help="Write native JSON report")
    typecheck.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    typecheck.add_argument("--junit", help="Write JUnit XML report")
    typecheck.add_argument("--markdown", help="Write Markdown report")
    typecheck.add_argument("--html", help="Write standalone HTML report")
    typecheck.add_argument("--ci", action="store_true")

    type_audit_cmd = sub.add_parser("type-audit", help="Run type-intelligence bridge and static type-contract checks")
    type_audit_cmd.add_argument("project")
    type_audit_cmd.add_argument("--engine", action="append", choices=["pyright", "mypy"], help="Type engine to run; repeat for multiple engines; default runs both")
    type_audit_cmd.add_argument("--timeout", type=int, default=300)
    type_audit_cmd.add_argument("--require-tools", action="store_true", help="Fail if requested type tools are unavailable")
    type_audit_cmd.add_argument("--fail-on-type-errors", action="store_true", help="Turn external type-checker errors into blocking findings")
    type_audit_cmd.add_argument("--max-untyped-public", type=int, help="Maximum allowed public functions/methods missing annotations")
    type_audit_cmd.add_argument("--summary-json", help="Write type audit summary JSON")
    type_audit_cmd.add_argument("--output", "-o", help="Write native JSON report")
    type_audit_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    type_audit_cmd.add_argument("--junit", help="Write JUnit XML report")
    type_audit_cmd.add_argument("--markdown", help="Write Markdown report")
    type_audit_cmd.add_argument("--html", help="Write standalone HTML report")
    type_audit_cmd.add_argument("--ci", action="store_true")

    external_cmd = sub.add_parser("external-audit", help="Bridge optional external analyzers through FindingCore")
    external_cmd.add_argument("project")
    external_cmd.add_argument("--tool", action="append", choices=["ruff", "bandit", "semgrep", "pip-audit"], help="Tool to run; repeat for multiple tools; default runs all supported")
    external_cmd.add_argument("--timeout", type=int, default=300)
    external_cmd.add_argument("--require-tools", action="store_true")
    external_cmd.add_argument("--summary-json", help="Write external audit summary JSON")
    external_cmd.add_argument("--output", "-o", help="Write native JSON report")
    external_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    external_cmd.add_argument("--junit", help="Write JUnit XML report")
    external_cmd.add_argument("--markdown", help="Write Markdown report")
    external_cmd.add_argument("--html", help="Write standalone HTML report")
    external_cmd.add_argument("--ci", action="store_true")

    deployment_cmd = sub.add_parser("deployment-audit", help="Audit Docker/GitHub Actions/systemd/nginx deployment contracts")
    deployment_cmd.add_argument("project")
    deployment_cmd.add_argument("--summary-json", help="Write deployment audit summary JSON")
    deployment_cmd.add_argument("--output", "-o", help="Write native JSON report")
    deployment_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    deployment_cmd.add_argument("--junit", help="Write JUnit XML report")
    deployment_cmd.add_argument("--markdown", help="Write Markdown report")
    deployment_cmd.add_argument("--html", help="Write standalone HTML report")
    deployment_cmd.add_argument("--ci", action="store_true")

    migration_cmd = sub.add_parser("migration-audit", help="Audit migration/schema lifecycle risks")
    migration_cmd.add_argument("project")
    migration_cmd.add_argument("--summary-json", help="Write migration audit summary JSON")
    migration_cmd.add_argument("--output", "-o", help="Write native JSON report")
    migration_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    migration_cmd.add_argument("--junit", help="Write JUnit XML report")
    migration_cmd.add_argument("--markdown", help="Write Markdown report")
    migration_cmd.add_argument("--html", help="Write standalone HTML report")
    migration_cmd.add_argument("--ci", action="store_true")

    supply_cmd = sub.add_parser("supply-chain-audit", help="Audit dependency pinning and supply-chain risk signals")
    supply_cmd.add_argument("project")
    supply_cmd.add_argument("--summary-json", help="Write supply-chain audit summary JSON")
    supply_cmd.add_argument("--output", "-o", help="Write native JSON report")
    supply_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    supply_cmd.add_argument("--junit", help="Write JUnit XML report")
    supply_cmd.add_argument("--markdown", help="Write Markdown report")
    supply_cmd.add_argument("--html", help="Write standalone HTML report")
    supply_cmd.add_argument("--ci", action="store_true")

    precision_cmd = sub.add_parser("precision-audit", help="Audit golden clean/expected corpus for false positives and known detections")
    precision_cmd.add_argument("corpus")
    precision_cmd.add_argument("--max-clean-issues", type=int, default=0)
    precision_cmd.add_argument("--summary-json", help="Write precision audit summary JSON")
    precision_cmd.add_argument("--output", "-o", help="Write native JSON report")
    precision_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    precision_cmd.add_argument("--junit", help="Write JUnit XML report")
    precision_cmd.add_argument("--markdown", help="Write Markdown report")
    precision_cmd.add_argument("--html", help="Write standalone HTML report")
    precision_cmd.add_argument("--ci", action="store_true")

    stress_cmd = sub.add_parser("stress-audit", help="Run synthetic large-project stress, memory and unknown-call budget checks")
    stress_cmd.add_argument("--files", type=int, default=500)
    stress_cmd.add_argument("--max-seconds", type=float, default=15.0)
    stress_cmd.add_argument("--max-peak-mb", type=float)
    stress_cmd.add_argument("--max-unknown-ratio", type=float, default=0.35)
    stress_cmd.add_argument("--summary-json", help="Write stress audit summary JSON")
    stress_cmd.add_argument("--output", "-o", help="Write native JSON report")
    stress_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    stress_cmd.add_argument("--junit", help="Write JUnit XML report")
    stress_cmd.add_argument("--markdown", help="Write Markdown report")
    stress_cmd.add_argument("--html", help="Write standalone HTML report")
    stress_cmd.add_argument("--ci", action="store_true")

    quality_cmd = sub.add_parser("quality-matrix", help="Run deterministic multi-domain quality gate matrix")
    quality_cmd.add_argument("project")
    quality_cmd.add_argument("--include-optional", action="store_true")
    quality_cmd.add_argument("--summary-json", help="Write quality matrix summary JSON")
    quality_cmd.add_argument("--output", "-o", help="Write native JSON report")
    quality_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    quality_cmd.add_argument("--junit", help="Write JUnit XML report")
    quality_cmd.add_argument("--markdown", help="Write Markdown report")
    quality_cmd.add_argument("--html", help="Write standalone HTML report")
    quality_cmd.add_argument("--ci", action="store_true")

    rule_quality_cmd = sub.add_parser("rule-quality", help="Audit rule quality passports: tests, coverage modes and known gaps")
    rule_quality_cmd.add_argument("project")
    rule_quality_cmd.add_argument("--registry", help="Path to docs/RULE_OWNERSHIP.json")
    rule_quality_cmd.add_argument("--summary-json", help="Write rule quality summary JSON")
    rule_quality_cmd.add_argument("--output", "-o", help="Write native JSON report")
    rule_quality_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    rule_quality_cmd.add_argument("--junit", help="Write JUnit XML report")
    rule_quality_cmd.add_argument("--markdown", help="Write Markdown report")
    rule_quality_cmd.add_argument("--html", help="Write standalone HTML report")
    rule_quality_cmd.add_argument("--ci", action="store_true")

    golden_cmd = sub.add_parser("golden-fixtures", help="Audit real-world/framework-specific golden expected fixtures")
    golden_cmd.add_argument("corpus")
    golden_cmd.add_argument("--summary-json", help="Write golden fixture summary JSON")
    golden_cmd.add_argument("--output", "-o", help="Write native JSON report")
    golden_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    golden_cmd.add_argument("--junit", help="Write JUnit XML report")
    golden_cmd.add_argument("--markdown", help="Write Markdown report")
    golden_cmd.add_argument("--html", help="Write standalone HTML report")
    golden_cmd.add_argument("--ci", action="store_true")

    ext_norm_cmd = sub.add_parser("external-normalize", help="Normalize Semgrep/Bandit/Ruff/Pyright JSON findings into native report format")
    ext_norm_cmd.add_argument("--tool", required=True, choices=["semgrep", "bandit", "ruff", "pyright"])
    ext_norm_cmd.add_argument("--input", required=True, help="External tool JSON output file")
    ext_norm_cmd.add_argument("--summary-json", help="Write normalization summary JSON")
    ext_norm_cmd.add_argument("--output", "-o", help="Write native JSON report")
    ext_norm_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    ext_norm_cmd.add_argument("--junit", help="Write JUnit XML report")
    ext_norm_cmd.add_argument("--markdown", help="Write Markdown report")
    ext_norm_cmd.add_argument("--html", help="Write standalone HTML report")
    ext_norm_cmd.add_argument("--ci", action="store_true")

    zipfix_cmd = sub.add_parser("zip-fixture-audit", help="Audit intentional duplicate zip-entry fixtures")
    zipfix_cmd.add_argument("project")
    zipfix_cmd.add_argument("--summary-json", help="Write zip fixture audit summary JSON")
    zipfix_cmd.add_argument("--output", "-o", help="Write native JSON report")
    zipfix_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    zipfix_cmd.add_argument("--junit", help="Write JUnit XML report")
    zipfix_cmd.add_argument("--markdown", help="Write Markdown report")
    zipfix_cmd.add_argument("--html", help="Write standalone HTML report")
    zipfix_cmd.add_argument("--ci", action="store_true")

    compat_cmd = sub.add_parser("compatibility-audit", help="Audit CLI and compatibility-regression command surface")
    compat_cmd.add_argument("project")
    compat_cmd.add_argument("--registry", help="Compatibility registry JSON path")
    compat_cmd.add_argument("--summary-json", help="Write compatibility audit summary JSON")
    compat_cmd.add_argument("--output", "-o", help="Write native JSON report")
    compat_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    compat_cmd.add_argument("--junit", help="Write JUnit XML report")
    compat_cmd.add_argument("--markdown", help="Write Markdown report")
    compat_cmd.add_argument("--html", help="Write standalone HTML report")
    compat_cmd.add_argument("--ci", action="store_true")

    owners_cmd = sub.add_parser("ownership-conflicts", help="Audit code ownership contradictions and governance counteraction signals")
    owners_cmd.add_argument("project")
    owners_cmd.add_argument("--summary-json", help="Write ownership conflict summary JSON")
    owners_cmd.add_argument("--output", "-o", help="Write native JSON report")
    owners_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    owners_cmd.add_argument("--junit", help="Write JUnit XML report")
    owners_cmd.add_argument("--markdown", help="Write Markdown report")
    owners_cmd.add_argument("--html", help="Write standalone HTML report")
    owners_cmd.add_argument("--ci", action="store_true")

    grep_cmd = sub.add_parser("grep-audit", help="Run configurable grep/regex pattern audit over repository text files")
    grep_cmd.add_argument("project")
    grep_cmd.add_argument("--pattern-file", help="JSON file with grep audit patterns")
    grep_cmd.add_argument("--regex", action="append", default=[], help="Inline pattern, optionally id:::regex; repeat for multiple")
    grep_cmd.add_argument("--include", action="append", default=[], help="Global include glob; repeat for multiple")
    grep_cmd.add_argument("--exclude", action="append", default=[], help="Global exclude glob; repeat for multiple")
    grep_cmd.add_argument("--no-builtins", action="store_true", help="Disable built-in high-confidence patterns")
    grep_cmd.add_argument("--max-matches", type=int, default=500, help="Stop after this many matches to avoid noisy reports")
    grep_cmd.add_argument("--summary-json", help="Write grep audit summary JSON")
    grep_cmd.add_argument("--output", "-o", help="Write native JSON report")
    grep_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    grep_cmd.add_argument("--junit", help="Write JUnit XML report")
    grep_cmd.add_argument("--markdown", help="Write Markdown report")
    grep_cmd.add_argument("--html", help="Write standalone HTML report")
    grep_cmd.add_argument("--ci", action="store_true")

    policy_cmd = sub.add_parser("policy-audit", help="Audit machine-readable quality policy as code")
    policy_cmd.add_argument("project")
    policy_cmd.add_argument("--policy", help="Quality policy JSON path; defaults to docs/QUALITY_POLICY.json")
    policy_cmd.add_argument("--summary-json", help="Write policy audit summary JSON")
    policy_cmd.add_argument("--output", "-o", help="Write native JSON report")
    policy_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    policy_cmd.add_argument("--junit", help="Write JUnit XML report")
    policy_cmd.add_argument("--markdown", help="Write Markdown report")
    policy_cmd.add_argument("--html", help="Write standalone HTML report")
    policy_cmd.add_argument("--ci", action="store_true")

    ci_profile_cmd = sub.add_parser("ci-profile-audit", help="Audit machine-readable CI profile contracts")
    ci_profile_cmd.add_argument("project")
    ci_profile_cmd.add_argument("--profiles", help="CI profiles JSON path; defaults to docs/CI_PROFILES.json")
    ci_profile_cmd.add_argument("--summary-json", help="Write CI profile audit summary JSON")
    ci_profile_cmd.add_argument("--output", "-o", help="Write native JSON report")
    ci_profile_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    ci_profile_cmd.add_argument("--junit", help="Write JUnit XML report")
    ci_profile_cmd.add_argument("--markdown", help="Write Markdown report")
    ci_profile_cmd.add_argument("--html", help="Write standalone HTML report")
    ci_profile_cmd.add_argument("--ci", action="store_true")

    release_evidence_cmd = sub.add_parser("release-evidence", help="Audit release evidence artifacts and manifest coverage")
    release_evidence_cmd.add_argument("project")
    release_evidence_cmd.add_argument("--summary-json", help="Write release evidence summary JSON")
    release_evidence_cmd.add_argument("--output", "-o", help="Write native JSON report")
    release_evidence_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    release_evidence_cmd.add_argument("--junit", help="Write JUnit XML report")
    release_evidence_cmd.add_argument("--markdown", help="Write Markdown report")
    release_evidence_cmd.add_argument("--html", help="Write standalone HTML report")
    release_evidence_cmd.add_argument("--ci", action="store_true")

    changed_cmd = sub.add_parser("changed-files-audit", help="Run deterministic audit over an explicit changed-files scope")
    changed_cmd.add_argument("project")
    changed_cmd.add_argument("--changed-file", action="append", default=[], help="Changed file path relative to project root; repeat for multiple")
    changed_cmd.add_argument("--changed-files-list", help="Text file containing changed paths, one per line")
    changed_cmd.add_argument("--extensions", nargs="+", default=list(DEFAULT_EXTENSIONS))
    changed_cmd.add_argument("--summary-json", help="Write changed-files audit summary JSON")
    changed_cmd.add_argument("--output", "-o", help="Write native JSON report")
    changed_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    changed_cmd.add_argument("--junit", help="Write JUnit XML report")
    changed_cmd.add_argument("--markdown", help="Write Markdown report")
    changed_cmd.add_argument("--html", help="Write standalone HTML report")
    changed_cmd.add_argument("--ci", action="store_true")

    scorecard_cmd = sub.add_parser("scorecard", help="Compute a deterministic quality scorecard from core gates")
    scorecard_cmd.add_argument("project")
    scorecard_cmd.add_argument("--min-score", type=int, default=85)
    scorecard_cmd.add_argument("--summary-json", help="Write scorecard summary JSON")
    scorecard_cmd.add_argument("--output", "-o", help="Write native JSON report")
    scorecard_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    scorecard_cmd.add_argument("--junit", help="Write JUnit XML report")
    scorecard_cmd.add_argument("--markdown", help="Write Markdown report")
    scorecard_cmd.add_argument("--html", help="Write standalone HTML report")
    scorecard_cmd.add_argument("--ci", action="store_true")

    pytest_cmd = sub.add_parser("pytest-audit", help="Run pytest and audit test-suite truthfulness hazards")
    pytest_cmd.add_argument("project")
    pytest_cmd.add_argument("--timeout", type=int, default=1800, help="pytest timeout in seconds")
    pytest_cmd.add_argument("--pytest-arg", action="append", default=[], help="Extra argument passed to pytest; repeat for multiple args")
    pytest_cmd.add_argument("--static-only", action="store_true", help="Only audit test files; do not run pytest")
    pytest_cmd.add_argument("--allow-plugin-autoload", action="store_true", help="Do not set PYTEST_DISABLE_PLUGIN_AUTOLOAD=1")
    pytest_cmd.add_argument("--semantic-completeness", action="store_true", help="Audit heuristic semantic test completeness signals")
    pytest_cmd.add_argument("--min-public-coverage", type=float, default=0.35, help="Minimum referenced public production-symbol ratio for semantic completeness audit")
    pytest_cmd.add_argument("--summary-json", help="Write pytest run summary and audit issues JSON")
    pytest_cmd.add_argument("--output", "-o", help="Write native JSON report")
    pytest_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    pytest_cmd.add_argument("--junit", help="Write JUnit XML report")
    pytest_cmd.add_argument("--markdown", help="Write Markdown report")
    pytest_cmd.add_argument("--html", help="Write standalone HTML report")
    pytest_cmd.add_argument("--ci", action="store_true")

    coverage_cmd = sub.add_parser("coverage-audit", help="Run coverage.py over pytest and enforce line/branch budgets")
    coverage_cmd.add_argument("project")
    coverage_cmd.add_argument("--timeout", type=int, default=1800)
    coverage_cmd.add_argument("--pytest-arg", action="append", default=[], help="Extra argument passed to pytest; repeat for multiple args")
    coverage_cmd.add_argument("--allow-plugin-autoload", action="store_true")
    coverage_cmd.add_argument("--min-lines", type=float, default=0.0, help="Minimum line coverage percentage")
    coverage_cmd.add_argument("--min-branches", type=float, help="Minimum branch coverage percentage")
    coverage_cmd.add_argument("--max-uncovered-files", type=int, help="Maximum measured files with uncovered lines")
    coverage_cmd.add_argument("--summary-json", help="Write coverage summary JSON")
    coverage_cmd.add_argument("--output", "-o", help="Write native JSON report")
    coverage_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    coverage_cmd.add_argument("--junit", help="Write JUnit XML report")
    coverage_cmd.add_argument("--markdown", help="Write Markdown report")
    coverage_cmd.add_argument("--html", help="Write standalone HTML report")
    coverage_cmd.add_argument("--ci", action="store_true")

    mutation_cmd = sub.add_parser("mutation-audit", help="Run conservative mutation-testing smoke checks against pytest")
    mutation_cmd.add_argument("project")
    mutation_cmd.add_argument("--timeout", type=int, default=1800)
    mutation_cmd.add_argument("--pytest-arg", action="append", default=[], help="Extra argument passed to pytest; repeat for multiple args")
    mutation_cmd.add_argument("--allow-plugin-autoload", action="store_true")
    mutation_cmd.add_argument("--max-mutants", type=int, default=20)
    mutation_cmd.add_argument("--min-score", type=float, help="Minimum killed-mutant score percentage")
    mutation_cmd.add_argument("--summary-json", help="Write mutation summary JSON")
    mutation_cmd.add_argument("--output", "-o", help="Write native JSON report")
    mutation_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    mutation_cmd.add_argument("--junit", help="Write JUnit XML report")
    mutation_cmd.add_argument("--markdown", help="Write Markdown report")
    mutation_cmd.add_argument("--html", help="Write standalone HTML report")
    mutation_cmd.add_argument("--ci", action="store_true")

    behavior_cmd = sub.add_parser("behavior-audit", help="Execute explicit production behavior contracts in isolated subprocesses")
    behavior_cmd.add_argument("project")
    behavior_cmd.add_argument("--spec", help="Behavior contract JSON with import/function/command probes")
    behavior_cmd.add_argument("--timeout", type=int, default=10, help="Per-probe timeout in seconds")
    behavior_cmd.add_argument("--import-smoke", action="store_true", help="Import discovered production modules as smoke probes")
    behavior_cmd.add_argument("--max-imports", type=int, default=50, help="Maximum import-smoke modules")
    behavior_cmd.add_argument("--deny-network", action="store_true", help="Block Python-probe socket creation and mark command probes with a network-disabled env flag")
    behavior_cmd.add_argument("--no-command-probes", action="store_true", help="Disable command probes for stricter behavior sandboxing")
    behavior_cmd.add_argument("--env-allowlist", action="append", default=[], help="Environment variable name allowed inside behavior subprocesses; repeat for multiple")
    behavior_cmd.add_argument("--deny-secret-env", action="store_true", help="Strip secret-like environment variables from behavior subprocesses")
    behavior_cmd.add_argument("--strict-sandbox", action="store_true", help="Apply the safest built-in behavior probe policy: deny Python sockets, disable command probes and strip secret-like environment variables")
    behavior_cmd.add_argument("--summary-json", help="Write behavior probe summary JSON")
    behavior_cmd.add_argument("--output", "-o", help="Write native JSON report")
    behavior_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    behavior_cmd.add_argument("--junit", help="Write JUnit XML report")
    behavior_cmd.add_argument("--markdown", help="Write Markdown report")
    behavior_cmd.add_argument("--html", help="Write standalone HTML report")
    behavior_cmd.add_argument("--ci", action="store_true")

    rules = sub.add_parser("list-rules", help="List deterministic rule catalog")
    rules.add_argument("--language", choices=["python", "javascript", "text"], help="Filter by rule language")
    rules.add_argument("--json", help="Write machine-readable rule coverage matrix")

    benchmark = sub.add_parser("benchmark", help="Run built-in benchmark fixtures")
    benchmark.add_argument("--output", "-o", help="Write benchmark metrics JSON")
    benchmark.add_argument("--ci", action="store_true", help="Return non-zero when benchmark expectations fail")

    adversarial_cmd = sub.add_parser("adversarial-suite", help="Run adversarial release/integrity acceptance fixtures")
    adversarial_cmd.add_argument("--output", "-o", help="Write native JSON report")
    adversarial_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    adversarial_cmd.add_argument("--junit", help="Write JUnit XML report")
    adversarial_cmd.add_argument("--markdown", help="Write Markdown report")
    adversarial_cmd.add_argument("--html", help="Write standalone HTML report")
    adversarial_cmd.add_argument("--summary-json", help="Write adversarial fixture inventory JSON")
    adversarial_cmd.add_argument("--ci", action="store_true")

    blindspot_cmd = sub.add_parser("blindspot-suite", help="Run regression fixtures for previously missed audit blind spots")
    blindspot_cmd.add_argument("--output", "-o", help="Write native JSON report")
    blindspot_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    blindspot_cmd.add_argument("--junit", help="Write JUnit XML report")
    blindspot_cmd.add_argument("--markdown", help="Write Markdown report")
    blindspot_cmd.add_argument("--html", help="Write standalone HTML report")
    blindspot_cmd.add_argument("--summary-json", help="Write blind-spot fixture inventory JSON")
    blindspot_cmd.add_argument("--ci", action="store_true")

    path_port_cmd = sub.add_parser("path-portability-suite", help="Run path portability and archive-name bypass acceptance fixtures")
    path_port_cmd.add_argument("--output", "-o", help="Write native JSON report")
    path_port_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    path_port_cmd.add_argument("--junit", help="Write JUnit XML report")
    path_port_cmd.add_argument("--markdown", help="Write Markdown report")
    path_port_cmd.add_argument("--html", help="Write standalone HTML report")
    path_port_cmd.add_argument("--summary-json", help="Write path-portability fixture inventory JSON")
    path_port_cmd.add_argument("--ci", action="store_true")

    structured_cmd = sub.add_parser("structured-hardening-suite", help="Run structured-file, Unicode-confusable and zip-directory hardening fixtures")
    structured_cmd.add_argument("--output", "-o", help="Write native JSON report")
    structured_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    structured_cmd.add_argument("--junit", help="Write JUnit XML report")
    structured_cmd.add_argument("--markdown", help="Write Markdown report")
    structured_cmd.add_argument("--html", help="Write standalone HTML report")
    structured_cmd.add_argument("--summary-json", help="Write structured-hardening fixture inventory JSON")
    structured_cmd.add_argument("--ci", action="store_true")

    encoded_cmd = sub.add_parser("encoded-collision-hardening-suite", help="Run encoded-separator, manifest-collision and structured-duplicate acceptance fixtures")
    encoded_cmd.add_argument("--output", "-o", help="Write native JSON report")
    encoded_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    encoded_cmd.add_argument("--junit", help="Write JUnit XML report")
    encoded_cmd.add_argument("--markdown", help="Write Markdown report")
    encoded_cmd.add_argument("--html", help="Write standalone HTML report")
    encoded_cmd.add_argument("--summary-json", help="Write encoded/collision fixture inventory JSON")
    encoded_cmd.add_argument("--ci", action="store_true")

    provenance_cmd = sub.add_parser("provenance-honesty-suite", help="Run audit-claim provenance and wording-honesty acceptance fixtures")
    provenance_cmd.add_argument("--output", "-o", help="Write native JSON report")
    provenance_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    provenance_cmd.add_argument("--junit", help="Write JUnit XML report")
    provenance_cmd.add_argument("--markdown", help="Write Markdown report")
    provenance_cmd.add_argument("--html", help="Write standalone HTML report")
    provenance_cmd.add_argument("--summary-json", help="Write provenance-honesty fixture inventory JSON")
    provenance_cmd.add_argument("--ci", action="store_true")


    claim_evidence_cmd = sub.add_parser("claim-evidence-contract-suite", help="Run claim evidence contract acceptance fixtures")
    claim_evidence_cmd.add_argument("--output", "-o", help="Write native JSON report")
    claim_evidence_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    claim_evidence_cmd.add_argument("--junit", help="Write JUnit XML report")
    claim_evidence_cmd.add_argument("--markdown", help="Write Markdown report")
    claim_evidence_cmd.add_argument("--html", help="Write standalone HTML report")
    claim_evidence_cmd.add_argument("--summary-json", help="Write claim-evidence fixture inventory JSON")
    claim_evidence_cmd.add_argument("--ci", action="store_true")

    claim_summary_cmd = sub.add_parser("claim-summary-verification-suite", help="Run claim-summary and verification-command hardening fixtures")
    claim_summary_cmd.add_argument("--output", "-o", help="Write native JSON report")
    claim_summary_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    claim_summary_cmd.add_argument("--junit", help="Write JUnit XML report")
    claim_summary_cmd.add_argument("--markdown", help="Write Markdown report")
    claim_summary_cmd.add_argument("--html", help="Write standalone HTML report")
    claim_summary_cmd.add_argument("--summary-json", help="Write claim-summary fixture inventory JSON")
    claim_summary_cmd.add_argument("--ci", action="store_true")

    evidence_safety_cmd = sub.add_parser("evidence-artifact-safety-suite", help="Run evidence/artifact path, command and identity safety fixtures")
    evidence_safety_cmd.add_argument("--output", "-o", help="Write native JSON report")
    evidence_safety_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    evidence_safety_cmd.add_argument("--junit", help="Write JUnit XML report")
    evidence_safety_cmd.add_argument("--markdown", help="Write Markdown report")
    evidence_safety_cmd.add_argument("--html", help="Write standalone HTML report")
    evidence_safety_cmd.add_argument("--summary-json", help="Write evidence-artifact fixture inventory JSON")
    evidence_safety_cmd.add_argument("--ci", action="store_true")

    array_ambiguity_cmd = sub.add_parser("array-ambiguity-suite", help="Run code array/registry/policy ambiguity acceptance fixtures")
    array_ambiguity_cmd.add_argument("--output", "-o", help="Write native JSON report")
    array_ambiguity_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    array_ambiguity_cmd.add_argument("--junit", help="Write JUnit XML report")
    array_ambiguity_cmd.add_argument("--markdown", help="Write Markdown report")
    array_ambiguity_cmd.add_argument("--html", help="Write standalone HTML report")
    array_ambiguity_cmd.add_argument("--summary-json", help="Write array-ambiguity fixture inventory JSON")
    array_ambiguity_cmd.add_argument("--ci", action="store_true")

    capabilities_cmd = sub.add_parser("capability-registry", help="Print the unified capability registry")
    capabilities_cmd.add_argument("--json", help="Write capability registry JSON")
    capabilities_cmd.add_argument("--validate", action="store_true", help="Validate registry invariants before printing")
    capabilities_cmd.add_argument("--ci", action="store_true")

    fuzz_cmd = sub.add_parser("fuzz-suite", help="Run deterministic property-style fuzz acceptance checks")
    fuzz_cmd.add_argument("--output", "-o", help="Write native JSON report")
    fuzz_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    fuzz_cmd.add_argument("--junit", help="Write JUnit XML report")
    fuzz_cmd.add_argument("--markdown", help="Write Markdown report")
    fuzz_cmd.add_argument("--html", help="Write standalone HTML report")
    fuzz_cmd.add_argument("--summary-json", help="Write fuzz fixture inventory JSON")
    fuzz_cmd.add_argument("--ci", action="store_true")

    mass_cmd = sub.add_parser("mass-audit", help="Audit project architecture mass and suite sprawl")
    mass_cmd.add_argument("project")
    mass_cmd.add_argument("--output", "-o", help="Write native JSON report")
    mass_cmd.add_argument("--summary-json", help="Write mass metrics JSON")
    mass_cmd.add_argument("--strict", action="store_true", help="Require capability registry for suite growth")
    mass_cmd.add_argument("--ci", action="store_true")

    dep_audit_cmd = sub.add_parser("dependency-audit", help="Audit dependency declarations and manifest consistency")
    dep_audit_cmd.add_argument("project")
    dep_audit_cmd.add_argument("--output", "-o", help="Write native JSON report")
    dep_audit_cmd.add_argument("--summary-json", help="Write dependency audit summary JSON")
    dep_audit_cmd.add_argument("--ci", action="store_true")

    validate_evidence_safety = sub.add_parser("validate-evidence-artifact-safety", help="Validate evidence/artifact safety in a fixes/audit JSON document")
    validate_evidence_safety.add_argument("report")
    validate_evidence_safety.add_argument("--output", "-o", help="Write native JSON report")
    validate_evidence_safety.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    validate_evidence_safety.add_argument("--junit", help="Write JUnit XML report")
    validate_evidence_safety.add_argument("--markdown", help="Write Markdown report")
    validate_evidence_safety.add_argument("--html", help="Write standalone HTML report")
    validate_evidence_safety.add_argument("--ci", action="store_true")

    validate_claim = sub.add_parser("validate-claim-evidence", help="Validate a fixes/audit claim-evidence JSON document")
    validate_claim.add_argument("report")
    validate_claim.add_argument("--output", "-o", help="Write native JSON report")
    validate_claim.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    validate_claim.add_argument("--junit", help="Write JUnit XML report")
    validate_claim.add_argument("--markdown", help="Write Markdown report")
    validate_claim.add_argument("--html", help="Write standalone HTML report")
    validate_claim.add_argument("--ci", action="store_true")

    validate_prov = sub.add_parser("validate-provenance", help="Validate a fixes/audit provenance JSON document")
    validate_prov.add_argument("report")
    validate_prov.add_argument("--output", "-o", help="Write native JSON report")
    validate_prov.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    validate_prov.add_argument("--junit", help="Write JUnit XML report")
    validate_prov.add_argument("--markdown", help="Write Markdown report")
    validate_prov.add_argument("--html", help="Write standalone HTML report")
    validate_prov.add_argument("--ci", action="store_true")

    assistant_caps = sub.add_parser("assistant-capabilities", help="List deterministic assistant-grade helper capabilities")
    assistant_caps.add_argument("--output", "-o", help="Write capability matrix JSON")

    explain = sub.add_parser("explain-report", help="Explain a native JSON report as an assistant-style review")
    explain.add_argument("report")
    explain.add_argument("--output", "-o", help="Write explanation to a file")
    explain.add_argument("--json", action="store_true", help="Write machine-readable JSON instead of Markdown")

    plan = sub.add_parser("review-plan", help="Build a P0/P1/P2 closure map from a native JSON report")
    plan.add_argument("report")
    plan.add_argument("--output", "-o", help="Write review plan JSON")

    patch = sub.add_parser("patch-plan", help="Build an ordered remediation queue from a native JSON report")
    patch.add_argument("report")
    patch.add_argument("--output", "-o", help="Write patch plan JSON")
    patch.add_argument("--max-items", type=int, default=40)

    prompts = sub.add_parser("prompt-pack", help="Print optional external LLM prompt packs")
    prompts.add_argument("--output", "-o", help="Write prompt pack JSON")

    limits = sub.add_parser("limitations", help="Print the machine-readable limitations registry")
    limits.add_argument("--output", "-o", help="Write limitations registry JSON")

    config_contract_cmd = sub.add_parser("config-contract", help="Audit env/config contract consistency")
    config_contract_cmd.add_argument("project")
    config_contract_cmd.add_argument("--output", "-o", help="Write native JSON report")
    config_contract_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    config_contract_cmd.add_argument("--junit", help="Write JUnit XML report")
    config_contract_cmd.add_argument("--markdown", help="Write Markdown report")
    config_contract_cmd.add_argument("--html", help="Write standalone HTML report")
    config_contract_cmd.add_argument("--ci", action="store_true")

    db_consistency_cmd = sub.add_parser("db-consistency", help="Audit SQLite/Postgres/MySQL backend consistency across code and config")
    db_consistency_cmd.add_argument("project")
    db_consistency_cmd.add_argument("--output", "-o", help="Write native JSON report")
    db_consistency_cmd.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    db_consistency_cmd.add_argument("--junit", help="Write JUnit XML report")
    db_consistency_cmd.add_argument("--markdown", help="Write Markdown report")
    db_consistency_cmd.add_argument("--html", help="Write standalone HTML report")
    db_consistency_cmd.add_argument("--ci", action="store_true")

    truth = sub.add_parser("truthfulness-gate", help="Audit documentation overclaims against explicit limitations")
    truth.add_argument("project")
    truth.add_argument("--output", "-o", help="Write native JSON report")
    truth.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    truth.add_argument("--junit", help="Write JUnit XML report")
    truth.add_argument("--markdown", help="Write Markdown report")
    truth.add_argument("--html", help="Write standalone HTML report")
    truth.add_argument("--ci", action="store_true")


    perf = sub.add_parser("performance-budget", help="Run a deterministic synthetic performance budget smoke test")
    perf.add_argument("--files", type=int, default=120)
    perf.add_argument("--max-seconds", type=float, default=8.0)
    perf.add_argument("--workers", type=int, default=1)
    perf.add_argument("--output", "-o", help="Write native JSON report")
    perf.add_argument("--json", help="Write performance metrics JSON")
    perf.add_argument("--ci", action="store_true")

    fixes = sub.add_parser("suggest-fixes", help="Build review-only safe fix suggestions from a native JSON report")
    fixes.add_argument("report")
    fixes.add_argument("--output", "-o", help="Write suggestions JSON")

    release = sub.add_parser("release-audit", help="Audit a release zip or project directory for version, report, CLI and archive integrity")
    release.add_argument("target")
    release.add_argument("--output", "-o", help="Write native JSON report")
    release.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    release.add_argument("--junit", help="Write JUnit XML report")
    release.add_argument("--markdown", help="Write Markdown report")
    release.add_argument("--html", help="Write standalone HTML report")
    release.add_argument("--skip-cli-matrix", action="store_true", help="Skip behavioral CLI smoke matrix")
    release.add_argument("--fail-on-skipped-tools", action="store_true", help="Treat skipped external verification tools as release-audit issues")
    release.add_argument("--adversarial-suite", action="store_true", help="Also run built-in adversarial acceptance fixtures")
    release.add_argument("--blindspot-suite", action="store_true", help="Also run blind-spot regression fixtures for previously missed release-audit edge cases")
    release.add_argument("--path-portability-suite", action="store_true", help="Also run path portability/archive-name bypass acceptance fixtures")
    release.add_argument("--structured-hardening-suite", action="store_true", help="Also run structured-file, Unicode-confusable and zip-directory hardening fixtures")
    release.add_argument("--encoded-collision-hardening-suite", action="store_true", help="Also run encoded-separator, manifest-collision and structured-duplicate hardening fixtures")
    release.add_argument("--provenance-honesty-suite", action="store_true", help="Also run audit-claim provenance and wording-honesty acceptance fixtures")
    release.add_argument("--claim-evidence-contract-suite", action="store_true", help="Also run claim evidence contract acceptance fixtures")
    release.add_argument("--claim-summary-verification-suite", action="store_true", help="Also run claim-summary and verification-command hardening fixtures")
    release.add_argument("--evidence-artifact-safety-suite", action="store_true", help="Also run evidence/artifact safety and verification-command injection fixtures")
    release.add_argument("--array-ambiguity-suite", action="store_true", help="Also run code array/registry/policy ambiguity fixtures")
    release.add_argument("--fuzz-suite", action="store_true", help="Also run deterministic property-style fuzz acceptance checks")
    release.add_argument("--mass-audit", action="store_true", help="Also run architecture mass audit on the unpacked release tree")
    release.add_argument("--dependency-audit", action="store_true", help="Also run dependency consistency audit on the unpacked release tree")
    release.add_argument("--capability-registry-check", action="store_true", help="Also validate the unified capability registry")
    release.add_argument("--ci", action="store_true")


    gh_cmd = sub.add_parser("github-integration", help="Emit GitHub Actions annotations and PR-comment markdown from a native report")
    gh_cmd.add_argument("report")
    gh_cmd.add_argument("--annotations")
    gh_cmd.add_argument("--pr-comment")
    gh_cmd.add_argument("--summary-json")
    gh_cmd.add_argument("--max-annotations", type=int, default=50)

    norm_packs_cmd = sub.add_parser("normalization-packs", help="List or run first-class external tool normalization packs")
    norm_packs_cmd.add_argument("--tool", choices=["semgrep", "bandit", "ruff", "pyright"])
    norm_packs_cmd.add_argument("--input")
    norm_packs_cmd.add_argument("--packs-json")
    norm_packs_cmd.add_argument("--output", "-o")
    norm_packs_cmd.add_argument("--sarif")
    norm_packs_cmd.add_argument("--ci", action="store_true")

    corpus_cmd = sub.add_parser("real-world-corpus", help="Create/audit a 20-50 project real-world corpus manifest")
    corpus_cmd.add_argument("--manifest", default="docs/REAL_WORLD_CORPUS_20.json")
    corpus_cmd.add_argument("--write-default", action="store_true")
    corpus_cmd.add_argument("--min-projects", type=int, default=20)
    corpus_cmd.add_argument("--require-local-paths", action="store_true")
    corpus_cmd.add_argument("--summary-json")
    corpus_cmd.add_argument("--ci", action="store_true")

    pr_bench_cmd = sub.add_parser("precision-recall-report", help="Compute recall/precision proxy from expected labels and observed native report")
    pr_bench_cmd.add_argument("--expected", required=True)
    pr_bench_cmd.add_argument("--observed", required=True)
    pr_bench_cmd.add_argument("--min-recall", type=float, default=0.80)
    pr_bench_cmd.add_argument("--min-precision-proxy", type=float, default=0.70)
    pr_bench_cmd.add_argument("--false-positive-budget", type=int, default=0)
    pr_bench_cmd.add_argument("--summary-json")
    pr_bench_cmd.add_argument("--output", "-o")
    pr_bench_cmd.add_argument("--ci", action="store_true")

    sarif_gh_cmd = sub.add_parser("sarif-github-audit", help="Validate SARIF upload-readiness for GitHub Code Scanning")
    sarif_gh_cmd.add_argument("sarif")
    sarif_gh_cmd.add_argument("--output", "-o")
    sarif_gh_cmd.add_argument("--ci", action="store_true")

    dashboard_cmd = sub.add_parser("dashboard", help="Build standalone HTML dashboard with trend bars from report JSON files")
    dashboard_cmd.add_argument("reports", nargs="+")
    dashboard_cmd.add_argument("--output", "-o", required=True)
    dashboard_cmd.add_argument("--title", default="AI Code Filter Trends")

    framework_cmd = sub.add_parser("framework-profile-audit", help="Run deeper framework profile checks")
    framework_cmd.add_argument("project")
    framework_cmd.add_argument("--profile", action="append", choices=["fastapi", "flask", "django", "sqlalchemy", "aiogram", "generic-messaging"])
    framework_cmd.add_argument("--summary-json")
    framework_cmd.add_argument("--output", "-o")
    framework_cmd.add_argument("--sarif")
    framework_cmd.add_argument("--ci", action="store_true")

    plugin_api_cmd = sub.add_parser("plugin-api-audit", help="Validate custom policy-pack plugin API manifest")
    plugin_api_cmd.add_argument("project")
    plugin_api_cmd.add_argument("--summary-json")
    plugin_api_cmd.add_argument("--output", "-o")
    plugin_api_cmd.add_argument("--ci", action="store_true")

    docker_box_cmd = sub.add_parser("docker-sandbox", help="Generate optional Docker sandbox command for behavior probes")
    docker_box_cmd.add_argument("project")
    docker_box_cmd.add_argument("--image", default="python:3.12-slim")
    docker_box_cmd.add_argument("--timeout", type=int, default=30)
    docker_box_cmd.add_argument("--summary-json")
    docker_box_cmd.add_argument("--ci", action="store_true")

    pr_mode_cmd = sub.add_parser("incremental-pr", help="Audit changed files plus call-graph neighborhood")
    pr_mode_cmd.add_argument("project")
    pr_mode_cmd.add_argument("--changed-file", action="append", default=[])
    pr_mode_cmd.add_argument("--changed-files-list")
    pr_mode_cmd.add_argument("--radius", type=int, default=1)
    pr_mode_cmd.add_argument("--summary-json")
    pr_mode_cmd.add_argument("--output", "-o")
    pr_mode_cmd.add_argument("--ci", action="store_true")

    gen_manifest = sub.add_parser("generate-manifest", help="Generate a SHA256 integrity manifest for a project/release tree")
    gen_manifest.add_argument("project")
    gen_manifest.add_argument("--output", "-o", help="Write manifest path; defaults to MANIFEST.sha256 inside the project")

    verify = sub.add_parser("verify-manifest", help="Verify a project/release tree against a SHA256 manifest")
    verify.add_argument("project")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--output", "-o", help="Write native JSON report")
    verify.add_argument("--sarif", help="Write SARIF 2.1.0 report")
    verify.add_argument("--junit", help="Write JUnit XML report")
    verify.add_argument("--markdown", help="Write Markdown report")
    verify.add_argument("--html", help="Write standalone HTML report")
    verify.add_argument("--ci", action="store_true")
    return parser


def _print_rules(language: str | None = None, json_output: str | None = None) -> None:
    catalog = build_default_catalog()
    write_coverage_matrix(catalog, json_output)
    rules = [rule for rule in catalog.rules if language is None or rule.language == language]
    print(f"Deterministic rules: {len(rules)}")
    matrix = coverage_matrix(catalog)
    print(f"Coverage: languages={matrix['by_language']} severities={matrix['by_severity']}")
    for rule in rules:
        print(f"{rule.rule_id}	{rule.severity.value}	{rule.language}	{rule.category}	{rule.title}")


def _finding_policy_from_args(args: argparse.Namespace) -> FindingPolicy:
    return FindingPolicy(
        max_critical=getattr(args, "max_critical", None),
        max_high=getattr(args, "max_high", None),
        max_medium=getattr(args, "max_medium", None),
        max_low=getattr(args, "max_low", None),
        fail_on_new=getattr(args, "fail_on_new", None),
        baseline_report=Path(args.baseline_report) if getattr(args, "baseline_report", None) else None,
    )


def _apply_governance(report, args: argparse.Namespace):
    core = FindingCore()
    suppressions, errors = core.load_suppressions(Path(args.suppressions) if getattr(args, "suppressions", None) else None)
    result = core.process(
        report,
        policy=_finding_policy_from_args(args),
        suppressions=suppressions,
        suppression_errors=errors,
    )
    return result.report, bool(result.gate_failures)


def _print_fingerprints(report) -> None:
    for issue in report.issues:
        print(f"FINGERPRINT	{issue_fingerprint(issue)}	{issue.file}	{issue.category}")

def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code. Raises AssertionError only for impossible parser states."""
    args = build_parser().parse_args(argv)

    if args.command == "github-integration":
        summary = write_github_outputs(args.report, annotations=getattr(args, "annotations", None), pr_comment=getattr(args, "pr_comment", None), summary_json=getattr(args, "summary_json", None), max_annotations=int(getattr(args, "max_annotations", 50)))
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "normalization-packs":
        write_pack_summary(getattr(args, "packs_json", None))
        if not getattr(args, "tool", None):
            print(json.dumps(list_packs(), ensure_ascii=False, indent=2))
            return 0
        if not getattr(args, "input", None):
            print("normalization-packs requires --input when --tool is set", file=sys.stderr)
            return 1
        report = normalize_with_pack(args.tool, args.input)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "real-world-corpus":
        if getattr(args, "write_default", False):
            write_default_corpus(args.manifest)
        report, summary = audit_corpus_manifest(args.manifest, min_projects=int(getattr(args, "min_projects", 20)), require_local_paths=bool(getattr(args, "require_local_paths", False)))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json(getattr(args, "summary_json", None), summary.to_dict())
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "precision-recall-report":
        report, summary = benchmark_precision_recall(args.expected, args.observed, min_recall=float(getattr(args, "min_recall", 0.8)), min_precision_proxy=float(getattr(args, "min_precision_proxy", 0.7)), false_positive_budget=int(getattr(args, "false_positive_budget", 0)))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_precision_recall_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "sarif-github-audit":
        report = audit_github_sarif(args.sarif)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "dashboard":
        write_trend_dashboard(list(args.reports), args.output, title=getattr(args, "title", "AI Code Filter Trends"))
        print(str(args.output))
        return 0

    if args.command == "framework-profile-audit":
        report, summary = audit_framework_profiles(args.project, profiles=tuple(getattr(args, "profile", None) or ("fastapi", "flask", "django", "sqlalchemy", "aiogram", "generic-messaging")))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_json(getattr(args, "summary_json", None), summary.to_dict())
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "plugin-api-audit":
        issues, summary = validate_plugin_manifest(args.project)
        report = __import__("ai_code_filter.models", fromlist=["Report"]).Report(); report.extend(issues)
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_json(getattr(args, "summary_json", None), summary.to_dict())
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "docker-sandbox":
        report, summary = build_behavior_sandbox_command(args.project, image=getattr(args, "image", "python:3.12-slim"), timeout=int(getattr(args, "timeout", 30)), dry_run=True)
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_docker_sandbox_summary(getattr(args, "summary_json", None), summary)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "incremental-pr":
        report, summary = audit_incremental_pr(args.project, changed_files=tuple(getattr(args, "changed_file", []) or ()), changed_files_list=getattr(args, "changed_files_list", None), radius=int(getattr(args, "radius", 1)))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_incremental_pr_summary(getattr(args, "summary_json", None), summary)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "baseline-audit":
        report = audit_baseline(args.baseline, project_root=getattr(args, "project_root", None), max_age_days=args.max_age_days, max_issues=getattr(args, "max_issues", None))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0
    if args.command == "rule-ownership":
        registry = Path(args.registry) if getattr(args, "registry", None) else Path(args.project) / "docs" / "RULE_OWNERSHIP.json"
        if getattr(args, "write_default", False):
            write_default_registry(registry)
        report = audit_rule_ownership(args.project, registry)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0
    if args.command == "inspect-deps":
        manifest = DependencyResolver(Path(args.project)).resolve()
        data = {
            "project_root": str(manifest.project_root),
            "python_dependencies": manifest.python_dependencies,
            "python_import_roots": manifest.python_import_roots,
            "javascript_dependencies": manifest.javascript_dependencies,
            "javascript_package_roots": manifest.javascript_package_roots,
            "lockfiles": manifest.lockfiles,
            "sources": manifest.sources,
        }
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_json(getattr(args, "output", None), data)
        return 0
    if args.command == "index-sdk":
        manifest = DependencyResolver(Path(args.project)).resolve()
        index = build_sdk_index(manifest, import_packages=bool(getattr(args, "import_packages", False)))
        write_sdk_index(index, args.output)
        print(json.dumps({"packages": len(index.packages), "imported": sum(1 for p in index.packages.values() if p.imported), "available": sum(1 for p in index.packages.values() if p.available)}, ensure_ascii=False, indent=2))
        return 0
    if args.command == "type-check":
        report = __import__("ai_code_filter.models", fromlist=["Report"]).Report()
        adapter = TypeToolAdapter(Path(args.project))
        for result in (adapter.run_pyright(), adapter.run_mypy()):
            if not result.available:
                report.record_skip(f"<{result.tool}>", result.raw_summary or f"{result.tool} executable not found")
                continue
            report.extend(result.issues)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        incomplete = bool(report.failed_files or report.skipped_files)
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or incomplete) else 0

    if args.command == "type-audit":
        report, summary = audit_type_intelligence(
            args.project,
            engines=tuple(getattr(args, "engine", None) or ("pyright", "mypy")),
            timeout=int(getattr(args, "timeout", 300)),
            require_tools=bool(getattr(args, "require_tools", False)),
            max_untyped_public=getattr(args, "max_untyped_public", None),
            fail_on_type_errors=bool(getattr(args, "fail_on_type_errors", False)),
        )
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_type_audit_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "external-audit":
        report, summary = audit_external_tools(
            args.project,
            tools=tuple(getattr(args, "tool", None) or ("ruff", "bandit", "semgrep", "pip-audit")),
            timeout=int(getattr(args, "timeout", 300)),
            require_tools=bool(getattr(args, "require_tools", False)),
        )
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_external_audit_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "deployment-audit":
        report = audit_deployment(args.project)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_deployment_summary(getattr(args, "summary_json", None), report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "migration-audit":
        report = audit_migrations(args.project)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_migration_summary(getattr(args, "summary_json", None), report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "supply-chain-audit":
        report = audit_supply_chain(args.project)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_supply_chain_summary(getattr(args, "summary_json", None), report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "precision-audit":
        report, summary = audit_precision_corpus(args.corpus, max_clean_issues=int(getattr(args, "max_clean_issues", 0)))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_precision_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "stress-audit":
        report, summary = audit_stress(files=int(getattr(args, "files", 500)), max_seconds=float(getattr(args, "max_seconds", 15.0)), max_peak_mb=getattr(args, "max_peak_mb", None), max_unknown_ratio=getattr(args, "max_unknown_ratio", 0.35))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_stress_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "quality-matrix":
        report, summary = audit_quality_matrix(args.project, include_optional=bool(getattr(args, "include_optional", False)))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_quality_matrix_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0


    if args.command == "rule-quality":
        report, summary = audit_rule_quality(args.project, registry_path=getattr(args, "registry", None))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_rule_quality_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "golden-fixtures":
        report, summary = audit_golden_fixtures(args.corpus)
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_golden_fixture_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "external-normalize":
        payload = Path(args.input).read_text(encoding="utf-8")
        report, summary = normalize_external_findings(args.tool, payload)
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_external_normalization_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "zip-fixture-audit":
        report, summary = audit_zip_fixtures(args.project)
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_zip_fixture_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "compatibility-audit":
        report, summary = audit_compatibility(args.project, registry=getattr(args, "registry", None))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_compatibility_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "ownership-conflicts":
        report, summary = audit_ownership_conflicts(args.project)
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_ownership_conflict_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "grep-audit":
        report, summary = audit_grep_patterns(
            args.project,
            pattern_file=getattr(args, "pattern_file", None),
            inline_patterns=tuple(getattr(args, "regex", []) or ()),
            include_builtins=not bool(getattr(args, "no_builtins", False)),
            include=tuple(getattr(args, "include", []) or ()),
            exclude=tuple(getattr(args, "exclude", []) or ()),
            max_matches=int(getattr(args, "max_matches", 500)),
        )
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_grep_audit_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "policy-audit":
        report, summary = audit_policy_as_code(args.project, policy_path=getattr(args, "policy", None))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_policy_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "ci-profile-audit":
        report, summary = audit_ci_profiles(args.project, profiles_path=getattr(args, "profiles", None))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_ci_profile_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "release-evidence":
        report, summary = audit_release_evidence(args.project)
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_release_evidence_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "changed-files-audit":
        report, summary = audit_changed_files(args.project, changed_files=tuple(getattr(args, "changed_file", []) or ()), changed_files_list=getattr(args, "changed_files_list", None), extensions=tuple(getattr(args, "extensions", []) or DEFAULT_EXTENSIONS))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_changed_files_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "scorecard":
        report, summary = audit_scorecard(args.project, min_score=int(getattr(args, "min_score", 85)))
        print_report(report)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_scorecard_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "pytest-audit":
        report, summary = audit_pytest(
            args.project,
            timeout=args.timeout,
            run=not getattr(args, "static_only", False),
            extra_args=getattr(args, "pytest_arg", []) or (),
            disable_plugin_autoload=not getattr(args, "allow_plugin_autoload", False),
            semantic_completeness=bool(getattr(args, "semantic_completeness", False)),
            min_public_coverage=float(getattr(args, "min_public_coverage", 0.35)),
        )
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_pytest_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "coverage-audit":
        report, summary = audit_coverage(
            args.project,
            timeout=int(getattr(args, "timeout", 1800)),
            pytest_args=tuple(getattr(args, "pytest_arg", []) or ()),
            disable_plugin_autoload=not bool(getattr(args, "allow_plugin_autoload", False)),
            min_lines=float(getattr(args, "min_lines", 0.0)),
            min_branches=getattr(args, "min_branches", None),
            max_uncovered_files=getattr(args, "max_uncovered_files", None),
        )
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_coverage_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "mutation-audit":
        report, summary = audit_mutation_lite(
            args.project,
            timeout=int(getattr(args, "timeout", 1800)),
            pytest_args=tuple(getattr(args, "pytest_arg", []) or ()),
            disable_plugin_autoload=not bool(getattr(args, "allow_plugin_autoload", False)),
            max_mutants=int(getattr(args, "max_mutants", 20)),
            min_score=getattr(args, "min_score", None),
        )
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_mutation_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "behavior-audit":
        report, summary = audit_behavior(
            args.project,
            spec=getattr(args, "spec", None),
            timeout=int(getattr(args, "timeout", 10)),
            import_smoke=bool(getattr(args, "import_smoke", False)),
            max_imports=int(getattr(args, "max_imports", 50)),
            deny_network=bool(getattr(args, "deny_network", False) or getattr(args, "strict_sandbox", False)),
            allow_commands=not bool(getattr(args, "no_command_probes", False) or getattr(args, "strict_sandbox", False)),
            env_allowlist=tuple(getattr(args, "env_allowlist", []) or ()),
            deny_secret_env=bool(getattr(args, "deny_secret_env", False) or getattr(args, "strict_sandbox", False)),
        )
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_behavior_summary(getattr(args, "summary_json", None), summary, report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0


    if args.command == "adversarial-suite":
        report = run_adversarial_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), adversarial_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "blindspot-suite":
        report = run_blindspot_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), blindspot_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "path-portability-suite":
        report = run_path_portability_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), path_portability_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0


    if args.command == "structured-hardening-suite":
        report = run_structured_hardening_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), structured_hardening_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "encoded-collision-hardening-suite":
        report = run_encoded_collision_hardening_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), encoded_collision_hardening_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "provenance-honesty-suite":
        report = run_provenance_honesty_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), provenance_honesty_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0



    if args.command == "claim-evidence-contract-suite":
        report = run_claim_evidence_contract_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), claim_evidence_contract_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "claim-summary-verification-suite":
        report = run_claim_summary_verification_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), claim_summary_verification_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "evidence-artifact-safety-suite":
        report = run_evidence_artifact_safety_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), evidence_artifact_safety_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "array-ambiguity-suite":
        report = run_array_ambiguity_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), array_ambiguity_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "capability-registry":
        report = validate_capability_registry(project_root=Path.cwd())
        data = capability_registry_summary()
        if getattr(args, "validate", False):
            data["validation_summary"] = report.summary()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_json(getattr(args, "json", None), data)
        if getattr(args, "validate", False) and report.issues:
            print_report(report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "fuzz-suite":
        report = run_fuzz_suite()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        write_json(getattr(args, "summary_json", None), fuzz_suite_summary())
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "mass-audit":
        report = run_mass_audit(Path(args.project), strict=bool(getattr(args, "strict", False)))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_json(getattr(args, "summary_json", None), mass_audit_summary(Path(args.project)))
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "dependency-audit":
        report = run_dependency_audit(Path(args.project))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_json(getattr(args, "summary_json", None), dependency_audit_summary(Path(args.project)))
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "validate-evidence-artifact-safety":
        report = validate_evidence_artifact_safety_file(Path(args.report))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "validate-claim-evidence":
        report = validate_claim_evidence_file(Path(args.report))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "validate-provenance":
        report = validate_provenance_file(Path(args.report))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "assistant-capabilities":
        data = assistant_capability_matrix()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_json(getattr(args, "output", None), data)
        return 0
    if args.command == "explain-report":
        report_data = load_native_report(args.report)
        explanation = explain_report(report_data, as_markdown=not bool(getattr(args, "json", False)))
        if getattr(args, "json", False):
            print(json.dumps(explanation, ensure_ascii=False, indent=2))
            write_json(getattr(args, "output", None), explanation)
        else:
            print(explanation)
            write_text(getattr(args, "output", None), explanation)
        return 0
    if args.command == "review-plan":
        data = build_review_plan(load_native_report(args.report))
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_json(getattr(args, "output", None), data)
        return 0
    if args.command == "patch-plan":
        data = build_patch_plan(load_native_report(args.report), max_items=max(1, int(getattr(args, "max_items", 40) or 40)))
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_json(getattr(args, "output", None), data)
        return 0
    if args.command == "prompt-pack":
        data = prompt_pack()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_json(getattr(args, "output", None), data)
        return 0
    if args.command == "limitations":
        data = limitation_registry()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_limitations(getattr(args, "output", None))
        return 0
    if args.command == "config-contract":
        report = audit_config_contract(args.project)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0
    if args.command == "db-consistency":
        report = audit_db_consistency(args.project)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0
    if args.command == "truthfulness-gate":
        report = validate_limitations_file(args.project)
        report.extend(run_truthfulness_gate(args.project).issues)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "performance-budget":
        report, metrics = run_performance_budget(files=args.files, max_seconds=args.max_seconds, workers=args.workers)
        print(json.dumps(metrics.to_dict(), ensure_ascii=False, indent=2))
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_json(getattr(args, "json", None), metrics.to_dict())
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0
    if args.command == "suggest-fixes":
        data = build_fix_suggestions_from_file(args.report)
        print(json.dumps(data, ensure_ascii=False, indent=2))
        write_json(getattr(args, "output", None), data)
        return 0

    if args.command == "release-audit":
        report = audit_release(args.target, run_cli_matrix=not bool(getattr(args, "skip_cli_matrix", False)), fail_on_skipped_tools=bool(getattr(args, "fail_on_skipped_tools", False)))
        if bool(getattr(args, "adversarial_suite", False)):
            adversarial_report = run_adversarial_suite()
            report.extend(adversarial_report.issues)
            for failed in adversarial_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in adversarial_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "blindspot_suite", False)):
            blindspot_report = run_blindspot_suite()
            report.extend(blindspot_report.issues)
            for failed in blindspot_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in blindspot_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "path_portability_suite", False)):
            path_port_report = run_path_portability_suite()
            report.extend(path_port_report.issues)
            for failed in path_port_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in path_port_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "structured_hardening_suite", False)):
            structured_report = run_structured_hardening_suite()
            report.extend(structured_report.issues)
            for failed in structured_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in structured_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "encoded_collision_hardening_suite", False)):
            encoded_report = run_encoded_collision_hardening_suite()
            report.extend(encoded_report.issues)
            for failed in encoded_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in encoded_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "provenance_honesty_suite", False)):
            provenance_report = run_provenance_honesty_suite()
            report.extend(provenance_report.issues)
            for failed in provenance_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in provenance_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "claim_evidence_contract_suite", False)):
            claim_report = run_claim_evidence_contract_suite()
            report.extend(claim_report.issues)
            for failed in claim_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in claim_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "claim_summary_verification_suite", False)):
            claim_summary_report = run_claim_summary_verification_suite()
            report.extend(claim_summary_report.issues)
            for failed in claim_summary_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in claim_summary_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "evidence_artifact_safety_suite", False)):
            evidence_safety_report = run_evidence_artifact_safety_suite()
            report.extend(evidence_safety_report.issues)
            for failed in evidence_safety_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in evidence_safety_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "array_ambiguity_suite", False)):
            array_report = run_array_ambiguity_suite()
            report.extend(array_report.issues)
            for failed in array_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in array_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "fuzz_suite", False)):
            fuzz_report = run_fuzz_suite()
            report.extend(fuzz_report.issues)
            for failed in fuzz_report.failed_files:
                report.record_failure(failed["file"], RuntimeError(failed["error"]))
            for skipped in fuzz_report.skipped_files:
                report.record_skip(skipped["file"], skipped["reason"])
        if bool(getattr(args, "capability_registry_check", False)):
            cap_report = validate_capability_registry(project_root=Path.cwd())
            report.extend(cap_report.issues)
        if bool(getattr(args, "mass_audit", False)) or bool(getattr(args, "dependency_audit", False)):
            extra_tmp, extra_root, _extra_name, extra_report = _copy_or_extract(Path(args.target))
            try:
                report.extend(extra_report.issues)
                for failed in extra_report.failed_files:
                    report.record_failure(failed["file"], RuntimeError(failed["error"]))
                for skipped in extra_report.skipped_files:
                    report.record_skip(skipped["file"], skipped["reason"])
                if bool(getattr(args, "mass_audit", False)):
                    mass_report = run_mass_audit(extra_root, strict=True)
                    report.extend(mass_report.issues)
                if bool(getattr(args, "dependency_audit", False)):
                    dep_report = run_dependency_audit(extra_root)
                    report.extend(dep_report.issues)
            finally:
                if extra_tmp is not None:
                    extra_tmp.cleanup()
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or report.skipped_files) else 0

    if args.command == "call-graph":
        graph = build_project_call_graph(args.paths, extensions=getattr(args, "extensions", [".py"]), max_files=int(getattr(args, "max_files", 10000) or 10000))
        write_call_graph(graph, args.output)
        print(json.dumps(graph.summary(), ensure_ascii=False, indent=2))
        report = audit_call_graph(graph, max_unknown_ratio=getattr(args, "max_unknown_ratio", None))
        write_json_report(report, getattr(args, "report", None))
        if report.issues:
            print_report(report)
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0

    if args.command == "generate-manifest":
        try:
            path = write_manifest(args.project, getattr(args, "output", None))
        except (OSError, ValueError) as exc:
            print(f"generate-manifest failed: {exc}", file=sys.stderr)
            return 1
        print(str(path))
        return 0
    if args.command == "verify-manifest":
        report = verify_manifest(args.project, args.manifest)
        print_report(report)
        write_json_report(report, getattr(args, "output", None))
        write_sarif_report(report, getattr(args, "sarif", None))
        write_junit_report(report, getattr(args, "junit", None))
        write_markdown_report(report, getattr(args, "markdown", None))
        write_html_report(report, getattr(args, "html", None))
        return 1 if getattr(args, "ci", False) and report.has_blocking_issues() else 0
    if args.command == "list-rules":
        _print_rules(getattr(args, "language", None), getattr(args, "json", None))
        return 0
    if args.command == "benchmark":
        bench = write_benchmark_report(getattr(args, "output", None))
        print(json.dumps(bench["metrics"], ensure_ascii=False, indent=2))
        return 1 if getattr(args, "ci", False) and not bench["passed"] else 0

    config = RuntimeConfig(model=getattr(args, "model", DEFAULT_MODEL), extensions=tuple(args.extensions), enable_ai_review=not getattr(args, "no_ai", False), enable_drift=not getattr(args, "no_drift", False), plugin_paths=tuple(getattr(args, "plugin", []) or ()), workers=max(1, int(getattr(args, "workers", 1) or 1)), enable_type_tools=bool(getattr(args, "type_tools", False)), enable_sdk_index=bool(getattr(args, "sdk_index", False)), enable_sdk_imports=bool(getattr(args, "import_packages", False)), enable_unknown_call_check=bool(getattr(args, "unknown_call_check", False)), sdk_index_output=getattr(args, "sdk_index_output", None), profiles=normalize_profiles(getattr(args, "profile", None)))
    pipeline = AnalysisPipeline(config)
    if args.command == "analyze":
        if getattr(args, "print_limitations", False):
            print(json.dumps(limitation_registry(), ensure_ascii=False, indent=2))
        report = pipeline.analyze_paths(args.paths)
    elif args.command == "baseline":
        report = pipeline.baseline_check(args.paths, args.baseline)
    elif args.command == "drift-check":
        report = pipeline.drift_check(args.project)
    else:
        raise AssertionError(args.command)
    report, gate_failed = _apply_governance(report, args)
    print_report(report)
    if getattr(args, "print_fingerprints", False):
        _print_fingerprints(report)
    write_json_report(report, getattr(args, "output", None))
    if args.command == "analyze" and getattr(args, "write_baseline", None):
        write_json_report(report, getattr(args, "write_baseline", None))
    write_sarif_report(report, getattr(args, "sarif", None))
    write_junit_report(report, getattr(args, "junit", None))
    write_markdown_report(report, getattr(args, "markdown", None))
    write_html_report(report, getattr(args, "html", None))
    return 1 if getattr(args, "ci", False) and (report.has_blocking_issues() or gate_failed) else 0


if __name__ == "__main__":
    sys.exit(main())
