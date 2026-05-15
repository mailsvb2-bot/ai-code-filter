from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .base import Analyzer
from ..models import FilePayload, Issue, Severity

IDENTITY_KEYS = ("id", "name", "key", "route", "path", "command", "event", "handler", "role", "capability", "permission", "subject")
ACTION_KEYS = ("action", "method", "operation")
RESOURCE_KEYS = ("resource", "path", "route", "scope", "target")
BOOLEAN_FLAG_KEYS = ("enabled", "active", "allow", "deny", "can_read", "can_write", "can_execute", "required", "default")
WILDCARD_VALUES = {"*", ".*", "all", "any", "/.*", "/**", "**"}
CONTEXT_HINTS = ("route", "routes", "handler", "handlers", "registry", "registries", "policy", "policies", "permission", "permissions", "feature", "features", "capability", "capabilities", "plugin", "plugins", "command", "commands", "event", "events", "role", "roles", "rule", "rules", "dispatch", "mapping")
IGNORED_SCALAR_DUPLICATES = {repr(""), repr(" "), repr("```"), repr(None)}


def _norm(value: object) -> str:
    return str(value).strip().casefold()


def _const(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, (int, float)):
        return -node.operand.value
    return _MISSING


_MISSING = object()


def _literal_key(node: ast.AST) -> str | None:
    value = _const(node)
    if value is _MISSING:
        return None
    if isinstance(value, (str, int, float, bool)) or value is None:
        return repr(value)
    return None


def _dict_literal(node: ast.Dict) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for k, v in zip(node.keys, node.values):
        if k is None:
            continue
        key = _const(k)
        if isinstance(key, str):
            value = _const(v)
            data[key] = None if value is _MISSING else value
    return data


def _node_location(payload: FilePayload, node: ast.AST) -> tuple[str | None, int | None]:
    line = getattr(node, "lineno", None)
    if line is None:
        return None, None
    lines = payload.content.splitlines()
    text = lines[line - 1].strip() if 0 <= line - 1 < len(lines) else None
    return text, line


class ArrayAmbiguityAnalyzer(Analyzer):
    """Detect ambiguous list/tuple/set literals used as registries, policies and maps."""

    name = "array_ambiguity"

    def analyze(self, payload: FilePayload) -> list[Issue]:
        rel = payload.relative_path.replace("\\", "/")
        if rel.startswith("tests/") or rel.endswith(("claim_evidence_contract.py", "claim_summary_verification.py", "evidence_artifact_safety.py")):
            # These files intentionally contain malformed/duplicate fixture payloads used to test validators.
            return []
        suffix = payload.path.suffix.lower()
        if suffix == ".py":
            return self._analyze_python(payload)
        if suffix in {".js", ".jsx", ".ts", ".tsx", ".json"}:
            return self._analyze_text_arrays(payload)
        return []

    def _issue(self, payload: FilePayload, rule: str, severity: Severity, description: str, recommendation: str, node: ast.AST | None = None, location: str | None = None, line_number: int | None = None) -> Issue:
        loc = location
        line = line_number
        if node is not None:
            loc, line = _node_location(payload, node)
        return Issue(
            file=payload.relative_path,
            category=f"{rule}: Array ambiguity",
            severity=severity,
            detector=self.name,
            description=description,
            recommendation=recommendation,
            location=loc,
            line_number=line,
        )

    def _analyze_python(self, payload: FilePayload) -> list[Issue]:
        try:
            tree = ast.parse(payload.content)
        except SyntaxError:
            return []
        parent_map = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        issues: list[Issue] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                if not self._is_registry_context(node, parent_map):
                    continue
                elements = list(node.elts)
                issues.extend(self._check_duplicate_scalars(payload, node, elements))
                issues.extend(self._check_pair_duplicates(payload, node, elements))
                issues.extend(self._check_dict_array(payload, node, elements))
        return issues

    def _is_registry_context(self, node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> bool:
        current = node
        for _ in range(4):
            parent = parent_map.get(current)
            if parent is None:
                return False
            if isinstance(parent, ast.Assign):
                names: list[str] = []
                for target in parent.targets:
                    if isinstance(target, ast.Name):
                        names.append(target.id)
                    elif isinstance(target, ast.Attribute):
                        names.append(target.attr)
                return any(any(h in name.lower() for h in CONTEXT_HINTS) for name in names)
            if isinstance(parent, ast.AnnAssign):
                target = parent.target
                name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""
                return any(h in name.lower() for h in CONTEXT_HINTS)
            if isinstance(parent, ast.keyword):
                return bool(parent.arg and any(h in parent.arg.lower() for h in CONTEXT_HINTS))
            if isinstance(parent, ast.Return):
                return False
            current = parent
        return False

    def _check_duplicate_scalars(self, payload: FilePayload, node: ast.AST, elements: list[ast.AST]) -> list[Issue]:
        keys: dict[str, ast.AST] = {}
        issues: list[Issue] = []
        simple_count = 0
        for element in elements:
            key = _literal_key(element)
            if key is None or key in IGNORED_SCALAR_DUPLICATES:
                continue
            simple_count += 1
            if key in keys:
                issues.append(self._issue(payload, "ARR001", Severity.MEDIUM, f"Duplicate scalar array entry {key} creates ambiguous enum/config semantics.", "Remove the duplicate or document intentional aliases in a structured mapping.", element))
            else:
                keys[key] = element
        return issues if simple_count >= 2 else []

    def _check_pair_duplicates(self, payload: FilePayload, node: ast.AST, elements: list[ast.AST]) -> list[Issue]:
        first_seen: dict[str, ast.AST] = {}
        issues: list[Issue] = []
        for element in elements:
            if not isinstance(element, (ast.List, ast.Tuple)) or len(element.elts) < 2:
                continue
            key = _literal_key(element.elts[0])
            if key is None:
                continue
            if key in first_seen:
                issues.append(self._issue(payload, "ARR002", Severity.HIGH, f"Duplicate first-column key {key} in array-of-pairs creates ambiguous dispatch/registry lookup.", "Use a dict with unique keys or merge the duplicate pair deliberately.", element))
            else:
                first_seen[key] = element
        return issues

    def _check_dict_array(self, payload: FilePayload, node: ast.AST, elements: list[ast.AST]) -> list[Issue]:
        dict_items: list[tuple[ast.Dict, dict[str, Any]]] = [(e, _dict_literal(e)) for e in elements if isinstance(e, ast.Dict)]
        if len(dict_items) < 2:
            return []
        issues: list[Issue] = []
        for key in IDENTITY_KEYS:
            seen: dict[str, ast.Dict] = {}
            for dict_node, data in dict_items:
                value = data.get(key)
                if not isinstance(value, (str, int, bool)):
                    continue
                nk = _norm(value)
                if nk in seen:
                    issues.append(self._issue(payload, "ARR003", Severity.HIGH, f"Duplicate {key!r} value {value!r} in array-of-dicts creates ambiguous registry/config ownership.", "Make registry/config identifiers unique or consolidate duplicated entries.", dict_node))
                else:
                    seen[nk] = dict_node
        issues.extend(self._check_policy_conflicts(payload, dict_items))
        issues.extend(self._check_boolean_conflicts(payload, dict_items))
        issues.extend(self._check_wildcard_order(payload, dict_items))
        return issues

    def _check_policy_conflicts(self, payload: FilePayload, dict_items: list[tuple[ast.Dict, dict[str, Any]]]) -> list[Issue]:
        issues: list[Issue] = []
        buckets: dict[tuple[str, str, str], dict[str, ast.Dict]] = defaultdict(dict)
        for node, data in dict_items:
            effect = data.get("effect") or ("allow" if data.get("allow") is True else "deny" if data.get("deny") is True else None)
            if not isinstance(effect, str):
                continue
            effect_norm = _norm(effect)
            if effect_norm not in {"allow", "deny"}:
                continue
            subject = _norm(data.get("subject") or data.get("role") or data.get("user") or "<any>")
            action = _norm(next((data.get(k) for k in ACTION_KEYS if data.get(k) is not None), "<any>"))
            resource = _norm(next((data.get(k) for k in RESOURCE_KEYS if data.get(k) is not None), "<any>"))
            bucket = buckets[(subject, action, resource)]
            if bucket and effect_norm not in bucket:
                issues.append(self._issue(payload, "ARR004", Severity.CRITICAL, f"Conflicting allow/deny policy entries for subject={subject}, action={action}, resource={resource}.", "Collapse policy entries into one canonical rule or add explicit priority semantics.", node))
            bucket[effect_norm] = node
        return issues

    def _check_boolean_conflicts(self, payload: FilePayload, dict_items: list[tuple[ast.Dict, dict[str, Any]]]) -> list[Issue]:
        issues: list[Issue] = []
        by_identity: dict[tuple[tuple[str, str], ...], dict[str, bool]] = defaultdict(dict)
        source_node: dict[tuple[tuple[str, str], ...], ast.Dict] = {}
        for node, data in dict_items:
            identity_pairs = []
            for key in ("id", "name", "key", "route", "command", "role", "subject", "action", "resource"):
                value = data.get(key)
                if isinstance(value, (str, int, bool)):
                    identity_pairs.append((key, _norm(value)))
            if not identity_pairs:
                continue
            ident = tuple(identity_pairs)
            source_node.setdefault(ident, node)
            for flag in BOOLEAN_FLAG_KEYS:
                value = data.get(flag)
                if isinstance(value, bool):
                    existing = by_identity[ident].get(flag)
                    if existing is not None and existing is not value:
                        issues.append(self._issue(payload, "ARR008", Severity.HIGH, f"Contradictory boolean flag {flag!r} for same registry/policy identity {dict(identity_pairs)}.", "Use one source of truth for boolean flags or encode precedence explicitly.", node))
                    by_identity[ident][flag] = value
        return issues

    def _check_wildcard_order(self, payload: FilePayload, dict_items: list[tuple[ast.Dict, dict[str, Any]]]) -> list[Issue]:
        issues: list[Issue] = []
        earlier_wildcards: list[tuple[ast.Dict, dict[str, Any], str]] = []
        for node, data in dict_items:
            pattern_key = next((k for k in ("pattern", "route", "path", "command", "event", "resource") if isinstance(data.get(k), str)), None)
            pattern = data.get(pattern_key) if pattern_key else None
            if isinstance(pattern, str) and _norm(pattern) in WILDCARD_VALUES:
                earlier_wildcards.append((node, data, pattern_key or "pattern"))
                continue
            if isinstance(pattern, str):
                for wild_node, wild_data, wild_key in earlier_wildcards:
                    same_scope = True
                    for key in ("subject", "role", "action", "method"):
                        if key in wild_data and key in data and _norm(wild_data[key]) != _norm(data[key]):
                            same_scope = False
                    if same_scope:
                        issues.append(self._issue(payload, "ARR005", Severity.MEDIUM, f"Broad wildcard {wild_key} rule appears before specific {pattern_key}={pattern!r}; ordering may make the specific rule unreachable.", "Move specific rules before catch-all rules or add explicit priority fields.", node))
                        break
        return issues

    def _analyze_text_arrays(self, payload: FilePayload) -> list[Issue]:
        text = payload.content
        issues: list[Issue] = []
        issues.extend(self._check_js_duplicate_route_pairs(payload, text))
        issues.extend(self._check_json_arrays(payload))
        return issues

    def _check_js_duplicate_route_pairs(self, payload: FilePayload, text: str) -> list[Issue]:
        issues: list[Issue] = []
        pair_re = re.compile(r"[\[({,]\s*['\"](?P<key>[/@\w:.-]+)['\"]\s*,")
        seen: dict[str, int] = {}
        for match in pair_re.finditer(text):
            key = match.group("key")
            nk = _norm(key)
            line = text.count("\n", 0, match.start()) + 1
            if nk in seen:
                issues.append(Issue(
                    file=payload.relative_path,
                    category="ARR006: Array ambiguity",
                    severity=Severity.HIGH,
                    detector=self.name,
                    description=f"Duplicate JavaScript/TypeScript array-of-pairs key {key!r}; handler/dispatch lookup may be ambiguous.",
                    recommendation="Use unique dispatch keys or a Map/object with explicit duplicate checks.",
                    line_number=line,
                    location=key,
                ))
            else:
                seen[nk] = line
        # Object arrays: { route: '/x' }, { route: '/x' }
        obj_key_re = re.compile(r"\b(?P<field>id|name|key|route|path|command|event|role|capability)\s*:\s*['\"](?P<value>[^'\"]+)['\"]")
        seen_fields: dict[tuple[str, str], int] = {}
        for match in obj_key_re.finditer(text):
            field, value = match.group("field"), match.group("value")
            nk = (field, _norm(value))
            line = text.count("\n", 0, match.start()) + 1
            if nk in seen_fields:
                issues.append(Issue(
                    file=payload.relative_path,
                    category="ARR003: Array ambiguity",
                    severity=Severity.HIGH,
                    detector=self.name,
                    description=f"Duplicate {field!r} value {value!r} in JavaScript/TypeScript config/registry objects.",
                    recommendation="Make registry identifiers unique or merge duplicated config entries.",
                    line_number=line,
                    location=match.group(0),
                ))
            else:
                seen_fields[nk] = line
        if re.search(r"effect\s*:\s*['\"]allow['\"][\s\S]{0,200}effect\s*:\s*['\"]deny['\"]", text) or re.search(r"effect\s*:\s*['\"]deny['\"][\s\S]{0,200}effect\s*:\s*['\"]allow['\"]", text):
            issues.append(Issue(file=payload.relative_path, category="ARR004: Array ambiguity", severity=Severity.HIGH, detector=self.name, description="JavaScript/TypeScript policy array contains nearby allow/deny effects; policy precedence may be ambiguous.", recommendation="Add explicit priority or consolidate conflicting policy rules."))
        return issues

    def _check_json_arrays(self, payload: FilePayload) -> list[Issue]:
        if payload.path.suffix.lower() != ".json":
            return []
        try:
            data = json.loads(payload.content)
        except json.JSONDecodeError:
            return []
        issues: list[Issue] = []
        def walk(value: Any, path: str) -> None:
            if isinstance(value, list):
                self._check_json_list(payload, value, path, issues)
                for i, item in enumerate(value):
                    walk(item, f"{path}[{i}]")
            elif isinstance(value, dict):
                for k, v in value.items():
                    walk(v, f"{path}.{k}" if path else str(k))
        walk(data, "$")
        return issues

    def _check_json_list(self, payload: FilePayload, arr: list[Any], path: str, issues: list[Issue]) -> None:
        scalars: dict[str, int] = {}
        for i, item in enumerate(arr):
            if isinstance(item, (str, int, float, bool)) or item is None:
                key = repr(item)
                if key in scalars:
                    issues.append(Issue(file=payload.relative_path, category="ARR001: Array ambiguity", severity=Severity.MEDIUM, detector=self.name, description=f"Duplicate scalar JSON array entry {key} at {path}.", recommendation="Remove duplicate JSON array values unless aliases are explicitly documented.", location=path))
                scalars[key] = i
        for id_key in IDENTITY_KEYS:
            seen: dict[str, int] = {}
            for i, item in enumerate(arr):
                if not isinstance(item, dict):
                    continue
                value = item.get(id_key)
                if not isinstance(value, (str, int, bool)):
                    continue
                nk = _norm(value)
                if nk in seen:
                    issues.append(Issue(file=payload.relative_path, category="ARR003: Array ambiguity", severity=Severity.HIGH, detector=self.name, description=f"Duplicate {id_key!r} value {value!r} in JSON array at {path}.", recommendation="Make JSON registry/config identifiers unique.", location=path))
                seen[nk] = i
