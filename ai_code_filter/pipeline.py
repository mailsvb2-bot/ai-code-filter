from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .analyzers.base import Analyzer
from .analyzers.contradictions import ContradictionAnalyzer
from .analyzers.deep_module import DeepModuleAnalyzer, build_module_index
from .analyzers.chain_inspector import ChainInspectorAnalyzer, build_chain_nodes
from .analyzers.fatigue import FatigueAnalyzer, compute_baseline_comment_ratio
from .analyzers.hidden_info import HiddenInformationAnalyzer
from .analyzers.polite_annoyance import PoliteAnnoyanceAnalyzer, compute_baseline_branch_entropy
from .analyzers.python_dataflow import PythonDataFlowAnalyzer
from .analyzers.python_cross_file_dataflow import PythonCrossFileDataFlowAnalyzer
from .analyzers.javascript_structure import JavaScriptStructureAnalyzer
from .analyzers.array_ambiguity import ArrayAmbiguityAnalyzer
from .analyzers.python_contract import PythonContractAnalyzer, compare_contracts
from .analyzers.rule_catalog import RuleCatalogAnalyzer
from .analyzers.unknown_calls import UnknownCallValidator
from .config_contract import ConfigContractAnalyzer
from .db_consistency import DBConsistencyAnalyzer
from .config import RuntimeConfig
from .drift import record_drift
from .filesystem import collect_files, infer_project_root, validate_text_file
from .llm.client import LLMReviewUnavailable, OpenAIReviewClient
from .models import FilePayload, Issue, Report, Severity
from .pipeline_integrity import validate_pipeline_integrity
from .plugins import load_plugin_rules
from .profiles import ProjectProfileAnalyzer
from .type_resolution.dependencies import DependencyResolver
from .type_resolution.sdk_index import build_sdk_index, write_sdk_index
from .type_resolution.type_tools import TypeToolAdapter
from .rules import RuleCatalog, build_default_catalog


class AnalysisPipeline:
    """Coordinates analyzers. It owns flow, but not detector logic."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def analyze_paths(self, paths: list[str]) -> Report:
        project_root = infer_project_root(paths)
        files = collect_files(paths, self.config.extensions)
        report = Report()
        report.extend(validate_pipeline_integrity(Path(__file__).resolve().parents[1]))
        if not files:
            report.add(Issue(file=str(project_root), category="Input", severity=Severity.HIGH, detector="pipeline", description="No matching files found.", recommendation="Check paths and extensions."))
            return report
        payloads = self._load_payloads(files, project_root, report)
        dependency_manifest = DependencyResolver(project_root).resolve()
        extra_import_roots = self._python_import_roots(payloads)
        sdk_index = build_sdk_index(dependency_manifest, self._safe_extra_import_roots(extra_import_roots, project_root), import_packages=self.config.enable_sdk_imports, import_allowlist=dependency_manifest.python_import_roots)
        if self.config.sdk_index_output:
            write_sdk_index(sdk_index, self.config.sdk_index_output)
        analyzers = self._build_analyzers(payloads, report, sdk_index)
        ai_client = OpenAIReviewClient(self.config) if self.config.enable_ai_review else None
        state_dir = self.config.state_dir(project_root)
        local_results = self._run_local_analyzers(payloads, analyzers)
        for payload in payloads:
            verdict = "UNKNOWN"
            if ai_client:
                try:
                    verdict, ai_issues = ai_client.review(payload)
                    report.extend(ai_issues)
                except LLMReviewUnavailable as exc:
                    report.add(Issue(file=payload.relative_path, category="AI review unavailable", severity=Severity.LOW, detector="ai_review", description=str(exc), recommendation="Set OPENAI_API_KEY and install openai to enable AI review."))
                    ai_client = None
                except Exception as exc:
                    report.record_failure(payload.relative_path, exc)
            issues, failures = local_results.get(payload.relative_path, ([], []))
            report.extend(issues)
            for exc in failures:
                report.record_failure(payload.relative_path, exc)
            if self.config.enable_drift:
                try:
                    report.extend(record_drift(payload.path, project_root, state_dir, verdict))
                except Exception as exc:
                    report.record_failure(payload.relative_path, exc)
        if self.config.enable_type_tools:
            adapter = TypeToolAdapter(project_root)
            for result in (adapter.run_pyright(), adapter.run_mypy()):
                if not result.available:
                    report.record_skip(f"<{result.tool}>", result.raw_summary or f"{result.tool} executable not found")
                    continue
                report.extend(result.issues)
        return report


    def _run_local_analyzers(self, payloads: list[FilePayload], analyzers: list[Analyzer]) -> dict[str, tuple[list[Issue], list[Exception]]]:
        if self.config.workers <= 1 or len(payloads) <= 1:
            return {payload.relative_path: self._analyze_payload(payload, analyzers) for payload in payloads}
        results: dict[str, tuple[list[Issue], list[Exception]]] = {}
        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            future_map = {pool.submit(self._analyze_payload, payload, analyzers): payload for payload in payloads}
            for future in as_completed(future_map):
                payload = future_map[future]
                try:
                    results[payload.relative_path] = future.result()
                except Exception as exc:
                    results[payload.relative_path] = ([], [exc])
        return results

    def _analyze_payload(self, payload: FilePayload, analyzers: list[Analyzer]) -> tuple[list[Issue], list[Exception]]:
        issues: list[Issue] = []
        failures: list[Exception] = []
        for analyzer in analyzers:
            try:
                issues.extend(analyzer.analyze(payload))
            except Exception as exc:
                failures.append(exc)
        return issues, failures

    def baseline_check(self, current_paths: list[str], baseline_path: str) -> Report:
        report = Report()
        baseline_root = Path(baseline_path).resolve()
        current_root = infer_project_root(current_paths)
        baseline_files = {self._relative_key(path, baseline_root): path for path in collect_files([baseline_path], self.config.extensions)}
        current_files = collect_files(current_paths, self.config.extensions)
        for current_file in current_files:
            key = self._relative_key(current_file, current_root)
            baseline_file = baseline_files.get(key)
            if not baseline_file:
                continue
            try:
                report.extend(compare_contracts(validate_text_file(baseline_file), validate_text_file(current_file), file=key))
            except Exception as exc:
                report.record_failure(key, exc)
        return report

    def drift_check(self, project: str) -> Report:
        project_root = Path(project).resolve()
        report = Report()
        state_dir = self.config.state_dir(project_root)
        for path in collect_files([project], self.config.extensions):
            try:
                report.extend(record_drift(path, project_root, state_dir, "UNKNOWN"))
            except Exception as exc:
                report.record_failure(str(path), exc)
        return report

    def _load_payloads(self, files: list[Path], project_root: Path, report: Report) -> list[FilePayload]:
        payloads: list[FilePayload] = []
        for path in files:
            try:
                payloads.append(FilePayload(path=path, project_root=project_root, content=validate_text_file(path)))
            except ValueError as exc:
                report.record_skip(str(path), str(exc))
            except Exception as exc:
                report.record_failure(str(path), exc)
        return payloads

    def _build_rule_catalog(self, report: Report) -> RuleCatalog:
        base_rules = list(build_default_catalog().rules)
        plugin_rules, errors = load_plugin_rules(self.config.plugin_paths)
        for error in errors:
            report.add(Issue(file="<plugin>", category="Plugin loading", severity=Severity.HIGH, detector="plugin_loader", description=error, recommendation="Fix or remove the plugin path."))
        return RuleCatalog([*base_rules, *plugin_rules])

    def _build_analyzers(self, payloads: list[FilePayload], report: Report, sdk_index=None) -> list[Analyzer]:
        module_index = build_module_index(payloads)
        chain_nodes = build_chain_nodes(payloads)
        catalog = self._build_rule_catalog(report)
        analyzers: list[Analyzer] = [
            ProjectProfileAnalyzer(self.config.profiles),
            PythonContractAnalyzer(),
            RuleCatalogAnalyzer(catalog),
            PythonDataFlowAnalyzer(),
            PythonCrossFileDataFlowAnalyzer(payloads),
            ConfigContractAnalyzer(payloads),
            DBConsistencyAnalyzer(payloads),
            JavaScriptStructureAnalyzer(),
            ArrayAmbiguityAnalyzer(),
            ChainInspectorAnalyzer(chain_nodes),
            HiddenInformationAnalyzer(),
            ContradictionAnalyzer(),
            FatigueAnalyzer(compute_baseline_comment_ratio(payloads)),
            PoliteAnnoyanceAnalyzer(compute_baseline_branch_entropy(payloads)),
            DeepModuleAnalyzer(module_index),
        ]
        if self.config.enable_unknown_call_check:
            analyzers.append(UnknownCallValidator(sdk_index))
        return analyzers

    def _python_import_roots(self, payloads: list[FilePayload]) -> set[str]:
        roots: set[str] = set()
        import ast
        for payload in payloads:
            if payload.path.suffix != ".py":
                continue
            try:
                tree = ast.parse(payload.content)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        roots.add(alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    roots.add(node.module)
        return roots

    def _safe_extra_import_roots(self, roots: set[str], project_root: Path) -> set[str]:
        """Keep resolver conservative: do not deep-index project-local modules as SDKs."""
        local_names = {p.stem for p in project_root.glob("*.py")} | {p.name for p in project_root.iterdir() if p.is_dir()}
        return {root for root in roots if root.split(".", 1)[0] not in local_names}

    def _relative_key(self, path: Path, root: Path) -> str:
        try:
            return str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            return path.name
