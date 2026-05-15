from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from ..models import FilePayload, Issue, Severity
from ..symbols import SymbolTable, build_symbol_table, call_name as _symbol_call_name, evidence_for_call

RuleCheck = Callable[[FilePayload, ast.AST | None], Iterable[Issue]]


@dataclass(frozen=True)
class Rule:
    """A deterministic rule with an explicit detector contract."""

    rule_id: str
    title: str
    severity: Severity
    language: str
    category: str
    check: RuleCheck
    rationale: str = ""


class RuleCatalog:
    """Owns deterministic rules. It is intentionally explicit, not prompt text."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules = tuple(rules)
        duplicated = _duplicates(rule.rule_id for rule in self._rules)
        if duplicated:
            raise ValueError(f"Duplicate rule ids: {', '.join(sorted(duplicated))}")

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def for_suffix(self, suffix: str) -> tuple[Rule, ...]:
        suffix = suffix.lower()
        if suffix == ".py":
            languages = {"python", "text"}
        elif suffix in {".js", ".ts", ".jsx", ".tsx"}:
            languages = {"javascript", "text"}
        else:
            languages = {"text"}
        return tuple(rule for rule in self._rules if rule.language in languages)

    def by_id(self) -> dict[str, Rule]:
        return {rule.rule_id: rule for rule in self._rules}

    def coverage(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for rule in self._rules:
            result[rule.language] = result.get(rule.language, 0) + 1
        return result


def _duplicates(values: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def issue(payload: FilePayload, rule: Rule, description: str, recommendation: str, node: ast.AST | None = None, location: str | None = None, line_number: int | None = None, *, confidence: str = "medium", evidence: dict | None = None) -> Issue:
    return Issue(
        file=payload.relative_path,
        category=f"{rule.rule_id}: {rule.category}",
        severity=rule.severity,
        detector="rule_catalog",
        description=description,
        recommendation=recommendation,
        location=location,
        line_number=line_number if line_number is not None else (getattr(node, "lineno", None) if node is not None else None),
        confidence=confidence,
        evidence=evidence,
    )


def line_issue(payload: FilePayload, rule: Rule, line_no: int, line: str, description: str, recommendation: str) -> Issue:
    return issue(payload, rule, description, recommendation, location=line.strip(), line_number=line_no)


def _call_name(node: ast.AST) -> str | None:
    return _symbol_call_name(node)


def _symbol_table(tree: ast.AST | None) -> SymbolTable:
    return build_symbol_table(tree)


def _resolved_call_name(node: ast.AST, symbols: SymbolTable) -> str | None:
    return symbols.canonical_call(node)


def _is_string_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _string_value(node: ast.AST) -> str:
    return str(getattr(node, "value", ""))


def _owner_name(stack: list[ast.AST]) -> str:
    owners = [getattr(node, "name", None) for node in stack if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
    return ".".join(str(x) for x in owners if x) or "<module>"


SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|messaging[_-]?bot[_-]?token)")
HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9_\-]{24,}")
MONEY_RE = re.compile(r"(?i)(amount|price|money|balance|cost|fee|rub|usd|eur|total|invoice|payment)")


def check_hardcoded_secret(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY001"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None or not _is_string_constant(value):
                continue
            text = _string_value(value)
            if len(text) < 8 or not HIGH_ENTROPY_RE.search(text):
                continue
            for target in targets:
                target_name = ast.unparse(target) if hasattr(ast, "unparse") else ""
                if SECRET_RE.search(target_name):
                    findings.append(issue(payload, rule, f"Hardcoded secret-like value assigned to {target_name}.", "Read secrets from environment or a secret manager; never commit token values.", node, ast.unparse(node)))
                    break
    return findings


def check_eval_exec(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY002"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in {"eval", "exec"}:
            findings.append(issue(payload, rule, f"Unsafe dynamic code execution via {_call_name(node.func)}().", "Replace eval/exec with explicit parsing or a safe dispatch table.", node, ast.unparse(node)))
    return findings


def check_silent_exception(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY003"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            body = [stmt for stmt in node.body if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str))]
            if body and all(isinstance(stmt, ast.Pass) for stmt in body):
                findings.append(issue(payload, rule, "Exception is silently swallowed with pass.", "Log the exception, re-raise it, or return an explicit error result.", node, ast.unparse(node)))
    return findings


def check_bare_except(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY004"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append(issue(payload, rule, "Bare except catches system-exiting exceptions and hides intent.", "Catch a specific exception type or re-raise unexpected errors.", node, ast.unparse(node)))
    return findings


def check_subprocess_shell_true(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY005"]
    findings: list[Issue] = []
    aliases = _symbol_table(tree)
    dangerous = {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _resolved_call_name(node.func, aliases) in dangerous:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(issue(payload, rule, "subprocess call uses shell=True.", "Pass an argument list with shell=False and validate all external input.", node, ast.unparse(node), confidence="high", evidence=evidence_for_call(aliases, node, reason="shell=True on subprocess boundary")))
    return findings


def check_pickle_loads(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY006"]
    findings: list[Issue] = []
    aliases = _symbol_table(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _resolved_call_name(node.func, aliases) in {"pickle.load", "pickle.loads"}:
            findings.append(issue(payload, rule, "pickle deserialization can execute code on untrusted data.", "Use JSON or a typed safe serializer for untrusted input.", node, ast.unparse(node), confidence="high", evidence=evidence_for_call(aliases, node, reason="pickle load/loads deserialization boundary")))
    return findings


def check_yaml_load_without_safe_loader(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY007"]
    findings: list[Issue] = []
    aliases = _symbol_table(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _resolved_call_name(node.func, aliases) != "yaml.load":
            continue
        has_safe_loader = any(kw.arg == "Loader" and "SafeLoader" in ast.unparse(kw.value) for kw in node.keywords)
        if not has_safe_loader:
            findings.append(issue(payload, rule, "yaml.load is used without SafeLoader.", "Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader).", node, ast.unparse(node), confidence="high", evidence=evidence_for_call(aliases, node, reason="yaml.load without explicit SafeLoader")))
    return findings


def check_requests_without_timeout(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY008"]
    methods = {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "requests.request"}
    findings: list[Issue] = []
    aliases = _symbol_table(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _resolved_call_name(node.func, aliases) in methods:
            if not any(kw.arg == "timeout" for kw in node.keywords):
                findings.append(issue(payload, rule, "HTTP request has no timeout.", "Set an explicit timeout and handle timeout errors.", node, ast.unparse(node), confidence="high", evidence=evidence_for_call(aliases, node, reason="requests call missing timeout keyword")))
    return findings


def check_async_time_sleep(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY009"]
    findings: list[Issue] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and _call_name(node.func) == "time.sleep":
                findings.append(issue(payload, rule, "Blocking time.sleep is used inside async function.", "Use await asyncio.sleep(...) or move blocking work to an executor.", node, ast.unparse(node)))
    return findings


def check_float_money_names(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY010"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if MONEY_RE.search(node.target.id) and ast.unparse(node.annotation) == "float":
                findings.append(issue(payload, rule, f"Money-like variable {node.target.id} is annotated as float.", "Use Decimal or integer minor units for money.", node, ast.unparse(node)))
    return findings


def check_mutable_default_args(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY011"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
            for default in defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    findings.append(issue(payload, rule, f"Function {node.name} uses a mutable default argument.", "Use None as the default and create the mutable value inside the function.", node, ast.unparse(default)))
    return findings


def check_os_system(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY012"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) == "os.system":
            findings.append(issue(payload, rule, "os.system executes through a shell boundary.", "Use subprocess.run with an argument list, shell=False, timeout, and checked results.", node, ast.unparse(node)))
    return findings


def check_tempfile_mktemp(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY013"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) == "tempfile.mktemp":
            findings.append(issue(payload, rule, "tempfile.mktemp is race-prone.", "Use NamedTemporaryFile, TemporaryDirectory, or mkstemp.", node, ast.unparse(node)))
    return findings


def check_assert_for_runtime_validation(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if payload.relative_path.startswith("tests/") or payload.relative_path.startswith("test_"):
        return []
    if tree is None:
        return []
    rule = RULES_BY_ID["PY014"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            findings.append(issue(payload, rule, "assert is used for runtime validation.", "Raise an explicit exception; asserts can be disabled with python -O.", node, ast.unparse(node)))
    return findings


def check_sql_string_interpolation(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY015"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call = _call_name(node.func) or ""
        if not call.endswith("execute") and not call.endswith("executemany"):
            continue
        if not node.args:
            continue
        query = node.args[0]
        if isinstance(query, ast.JoinedStr) or isinstance(query, ast.BinOp) or (isinstance(query, ast.Call) and _call_name(query.func) == "format"):
            findings.append(issue(payload, rule, "SQL query appears to be built through string interpolation.", "Use parameterized queries and pass values separately.", node, ast.unparse(node)))
    return findings


def check_asyncio_create_task_untracked(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY016"]
    findings: list[Issue] = []
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) == "asyncio.create_task":
            parent = parents.get(node)
            if isinstance(parent, ast.Expr):
                findings.append(issue(payload, rule, "asyncio.create_task result is not retained or supervised.", "Store the task, await it through a task group, or register it in a scheduler.", node, ast.unparse(node)))
    return findings


def check_weak_hash(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY017"]
    findings: list[Issue] = []
    aliases = _symbol_table(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _resolved_call_name(node.func, aliases) in {"hashlib.md5", "hashlib.sha1"}:
            findings.append(issue(payload, rule, "Weak hash function is used.", "Use SHA-256/BLAKE2 for integrity, or a password hashing function for passwords.", node, ast.unparse(node)))
    return findings


def check_naive_datetime_now(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY018"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in {"datetime.now", "datetime.utcnow"}:
            if _call_name(node.func) == "datetime.utcnow" or not node.args and not node.keywords:
                findings.append(issue(payload, rule, "Naive datetime is created.", "Use timezone-aware datetime, e.g. datetime.now(timezone.utc).", node, ast.unparse(node)))
    return findings


def check_wildcard_import(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY019"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            findings.append(issue(payload, rule, "Wildcard import hides dependencies and can shadow names.", "Import explicit symbols or the module namespace.", node, ast.unparse(node)))
    return findings


def check_open_without_encoding(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY020"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) == "open":
            has_encoding = any(kw.arg == "encoding" for kw in node.keywords)
            mode = "r"
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                mode = node.args[1].value
            binary = "b" in mode
            if not has_encoding and not binary:
                findings.append(issue(payload, rule, "Text file is opened without explicit encoding.", "Pass encoding='utf-8' or another intentional encoding.", node, ast.unparse(node)))
    return findings


def check_logging_secret_like_value(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY021"]
    findings: list[Issue] = []
    logging_calls = {"logging.debug", "logging.info", "logging.warning", "logging.error", "logging.exception", "log.debug", "log.info", "log.warning", "log.error", "log.exception"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in logging_calls:
            rendered = ast.unparse(node)
            if SECRET_RE.search(rendered):
                findings.append(issue(payload, rule, "Log statement references secret-like data.", "Mask tokens/passwords before logging or omit them entirely.", node, rendered))
    return findings


def check_request_json_silent(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    # Conservative rule: requests.Response.json() without surrounding try is frequently a fragile parsing boundary.
    if tree is None:
        return []
    rule = RULES_BY_ID["PY022"]
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    def inside_try(n: ast.AST) -> bool:
        cur = parents.get(n)
        while cur is not None:
            if isinstance(cur, ast.Try):
                return True
            cur = parents.get(cur)
        return False
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node.func)
        if call_name and call_name.endswith(".json") and not inside_try(node):
            findings.append(issue(payload, rule, "JSON parsing result is not protected by error handling.", "Catch parse errors at network/deserialization boundaries and return typed errors.", node, ast.unparse(node)))
    return findings


def check_insecure_random_for_secret(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY023"]
    findings: list[Issue] = []
    random_calls = {"random.random", "random.randint", "random.randrange", "random.choice", "random.choices"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            rendered = ast.unparse(node)
            target = ",".join(ast.unparse(t) for t in node.targets)
            if SECRET_RE.search(target) and any(name in rendered for name in random_calls):
                findings.append(issue(payload, rule, "Secret-like value is generated with non-cryptographic random.", "Use secrets.token_urlsafe, secrets.randbelow, or os.urandom-backed APIs.", node, rendered))
    return findings


# ---- Text and JavaScript/TypeScript rules ---------------------------------


def check_claimed_final_production(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["TXT001"]
    findings: list[Issue] = []
    header_prefixes = ("#", "//", "/*", "*", '"""', "'''")
    for line_no, line in enumerate(payload.content.splitlines()[:30], start=1):
        stripped = line.strip()
        if not (stripped.startswith(header_prefixes) or line_no <= 5):
            continue
        lower = stripped.lower()
        if "complete" in lower and "final" in lower and "production" in lower:
            findings.append(line_issue(payload, rule, line_no, line, "Header claims final production completeness.", "Replace marketing certainty with tested capability statements and versioned limitations."))
    return findings


def check_todo_markers(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if payload.relative_path.startswith("tests/") or payload.relative_path.startswith("test_"):
        return []
    rule = RULES_BY_ID["TXT002"]
    findings: list[Issue] = []
    pat = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if "pat = re.compile" in line or "re.findall" in line:
            continue
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "Unresolved work marker remains in audited code.", "Convert it into a tracked issue or finish/remove the incomplete work."))
    return findings


def check_suppression_comments(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if payload.relative_path.startswith("tests/") or payload.relative_path.startswith("test_"):
        return []
    rule = RULES_BY_ID["TXT003"]
    findings: list[Issue] = []
    pat = re.compile(r"\b(noqa|type:\s*ignore|eslint-disable|ts-ignore|nosec)\b", re.IGNORECASE)
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if "pat = re.compile" in line or "re.findall" in line:
            continue
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "Static-analysis suppression comment is present.", "Require a reason, scope the suppression to one rule, and review it periodically."))
    return findings


def check_js_eval(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS001"]
    findings: list[Issue] = []
    pat = re.compile(r"\beval\s*\(")
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "JavaScript eval executes dynamic code.", "Replace eval with explicit parsing or a safe dispatch table."))
    return findings


def check_js_inner_html(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS002"]
    findings: list[Issue] = []
    pat = re.compile(r"\.innerHTML\s*=")
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "innerHTML assignment can introduce XSS.", "Use textContent, sanitized templates, or a vetted sanitizer."))
    return findings


def check_js_secret_local_storage(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS003"]
    findings: list[Issue] = []
    pat = re.compile(r"localStorage\.(setItem|getItem)\s*\([^\n]*(token|secret|password|apiKey)", re.IGNORECASE)
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "Secret-like data is stored or read through localStorage.", "Keep secrets server-side or use short-lived HttpOnly secure cookies."))
    return findings


def check_js_console_log(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS004"]
    findings: list[Issue] = []
    pat = re.compile(r"\bconsole\.(log|debug|info)\s*\(")
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "Console logging remains in application code.", "Route diagnostics through a structured logger and remove noisy browser logs."))
    return findings


def check_js_dangerous_react_html(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS005"]
    findings: list[Issue] = []
    pat = re.compile(r"dangerouslySetInnerHTML")
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "React dangerouslySetInnerHTML is used.", "Sanitize the HTML at the boundary and document the trusted source."))
    return findings



def check_requests_verify_false(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY024"]
    findings: list[Issue] = []
    aliases = _symbol_table(tree)
    for node in ast.walk(tree):
        name = _resolved_call_name(node.func, aliases) if isinstance(node, ast.Call) else None
        if isinstance(node, ast.Call) and name and name.startswith("requests."):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    findings.append(issue(payload, rule, "TLS certificate verification is disabled for an HTTP request.", "Remove verify=False and fix certificate trust explicitly.", node, ast.unparse(node), confidence="high", evidence=evidence_for_call(aliases, node, reason="requests call sets verify=False")))
    return findings


def check_urllib_without_timeout(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY025"]
    findings: list[Issue] = []
    names = {"urllib.request.urlopen", "urlopen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in names:
            if not any(kw.arg == "timeout" for kw in node.keywords):
                findings.append(issue(payload, rule, "urllib request has no timeout.", "Pass an explicit timeout and handle timeout errors.", node, ast.unparse(node)))
    return findings


def check_insecure_ssl_context(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY026"]
    findings: list[Issue] = []
    bad_names = {"ssl._create_unverified_context", "_create_unverified_context"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in bad_names:
            findings.append(issue(payload, rule, "Unverified TLS context disables certificate validation.", "Use ssl.create_default_context and keep verification enabled.", node, ast.unparse(node)))
    return findings


def check_flask_debug_true(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY027"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in {"app.run", "run"}:
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(issue(payload, rule, "Debug server mode is enabled.", "Disable debug mode outside local development and control it through environment-specific config.", node, ast.unparse(node)))
    return findings


def check_django_debug_true(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    if tree is None:
        return []
    rule = RULES_BY_ID["PY028"]
    findings: list[Issue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                    findings.append(issue(payload, rule, "Django-style DEBUG=True is present.", "Load DEBUG from environment and make production default false.", node, ast.unparse(node)))
    return findings


def check_js_document_cookie_assignment(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS006"]
    findings: list[Issue] = []
    pat = re.compile(r"document\.cookie\s*=")
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "JavaScript writes document.cookie directly.", "Prefer server-set HttpOnly Secure SameSite cookies."))
    return findings


def check_js_target_blank_without_rel(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS007"]
    findings: list[Issue] = []
    pat = re.compile(r"target=[\"']_blank[\"']", re.IGNORECASE)
    rel_pat = re.compile(r"rel=[\"'][^\"']*(noopener|noreferrer)", re.IGNORECASE)
    for line_no, line in enumerate(payload.content.splitlines(), start=1):
        if pat.search(line) and not rel_pat.search(line):
            findings.append(line_issue(payload, rule, line_no, line, "External blank-target link lacks noopener/noreferrer.", "Add rel=\"noopener noreferrer\" to prevent reverse tabnabbing."))
    return findings


def check_js_fetch_without_error_boundary(payload: FilePayload, tree: ast.AST | None) -> list[Issue]:
    rule = RULES_BY_ID["JS008"]
    findings: list[Issue] = []
    lines = payload.content.splitlines()
    for line_no, line in enumerate(lines, start=1):
        if "fetch(" not in line:
            continue
        window = "\n".join(lines[max(0, line_no - 3): min(len(lines), line_no + 3)])
        if ".catch(" not in window and "try" not in window:
            findings.append(line_issue(payload, rule, line_no, line, "fetch call has no nearby error boundary.", "Wrap fetch in try/catch or attach a catch handler with explicit failure behavior."))
    return findings


_RULE_DEFINITIONS = (
    ("PY001", "Hardcoded secret-like value", Severity.CRITICAL, "python", "Security", check_hardcoded_secret, "Secrets must not be committed."),
    ("PY002", "Unsafe eval/exec", Severity.CRITICAL, "python", "Security", check_eval_exec, "Dynamic code execution is unsafe by default."),
    ("PY003", "Silent exception suppression", Severity.HIGH, "python", "Error handling", check_silent_exception, "Auditors must not hide failed execution paths."),
    ("PY004", "Bare except", Severity.HIGH, "python", "Error handling", check_bare_except, "Bare handlers catch BaseException subclasses."),
    ("PY005", "subprocess shell=True", Severity.CRITICAL, "python", "Security", check_subprocess_shell_true, "Shell boundaries require explicit review."),
    ("PY006", "Unsafe pickle deserialization", Severity.CRITICAL, "python", "Security", check_pickle_loads, "Pickle is code execution for untrusted input."),
    ("PY007", "Unsafe yaml.load", Severity.HIGH, "python", "Security", check_yaml_load_without_safe_loader, "Unsafe loaders can instantiate arbitrary objects."),
    ("PY008", "HTTP request without timeout", Severity.MEDIUM, "python", "Network", check_requests_without_timeout, "Network calls must have bounded latency."),
    ("PY009", "Blocking sleep in async function", Severity.HIGH, "python", "Async", check_async_time_sleep, "Blocking sleeps stall the event loop."),
    ("PY010", "Money represented as float", Severity.HIGH, "python", "Numeric correctness", check_float_money_names, "Money requires Decimal or minor units."),
    ("PY011", "Mutable default argument", Severity.HIGH, "python", "Correctness", check_mutable_default_args, "Mutable defaults leak state across calls."),
    ("PY012", "os.system shell execution", Severity.CRITICAL, "python", "Security", check_os_system, "Shell execution bypasses structured process contracts."),
    ("PY013", "tempfile.mktemp race", Severity.HIGH, "python", "Filesystem", check_tempfile_mktemp, "mktemp is race-prone."),
    ("PY014", "assert used for runtime validation", Severity.MEDIUM, "python", "Validation", check_assert_for_runtime_validation, "Assertions can be optimized away."),
    ("PY015", "SQL string interpolation", Severity.CRITICAL, "python", "Database security", check_sql_string_interpolation, "SQL values must be parameterized."),
    ("PY016", "Untracked asyncio task", Severity.HIGH, "python", "Async", check_asyncio_create_task_untracked, "Background tasks need ownership and failure handling."),
    ("PY017", "Weak hash function", Severity.MEDIUM, "python", "Cryptography", check_weak_hash, "MD5/SHA1 are weak for security-sensitive use."),
    ("PY018", "Naive datetime", Severity.MEDIUM, "python", "Time correctness", check_naive_datetime_now, "Distributed systems need timezone-aware timestamps."),
    ("PY019", "Wildcard import", Severity.MEDIUM, "python", "Maintainability", check_wildcard_import, "Wildcard imports hide dependencies."),
    ("PY020", "open without encoding", Severity.LOW, "python", "Portability", check_open_without_encoding, "Text encoding should be explicit."),
    ("PY021", "Secret-like data in logs", Severity.HIGH, "python", "Security", check_logging_secret_like_value, "Logs are a common data leak boundary."),
    ("PY022", "Unprotected response.json", Severity.LOW, "python", "Deserialization", check_request_json_silent, "Network JSON parsing is a failure boundary."),
    ("PY023", "Insecure random for secret", Severity.HIGH, "python", "Security", check_insecure_random_for_secret, "Secrets need cryptographic randomness."),
    ("PY024", "requests verify=False", Severity.HIGH, "python", "Network security", check_requests_verify_false, "TLS verification must stay enabled."),
    ("PY025", "urllib without timeout", Severity.MEDIUM, "python", "Network", check_urllib_without_timeout, "Network calls must have bounded latency."),
    ("PY026", "Unverified SSL context", Severity.HIGH, "python", "Network security", check_insecure_ssl_context, "TLS contexts must verify certificates."),
    ("PY027", "Debug server mode", Severity.HIGH, "python", "Configuration", check_flask_debug_true, "Debug mode must not leak into deployed runtime."),
    ("PY028", "DEBUG=True setting", Severity.HIGH, "python", "Configuration", check_django_debug_true, "Production configuration must default to safe settings."),
    ("TXT001", "False final-production claim", Severity.HIGH, "text", "False capability claim", check_claimed_final_production, "Claims must match implemented capability."),
    ("TXT002", "Unresolved work marker", Severity.LOW, "text", "Incomplete work", check_todo_markers, "Untracked TODOs hide debt."),
    ("TXT003", "Static-analysis suppression", Severity.MEDIUM, "text", "Suppression hygiene", check_suppression_comments, "Suppressions need reasons and scope."),
    ("JS001", "JavaScript eval", Severity.CRITICAL, "javascript", "Security", check_js_eval, "eval is unsafe in browser/server JS."),
    ("JS002", "innerHTML assignment", Severity.HIGH, "javascript", "XSS", check_js_inner_html, "Raw HTML assignment is an XSS boundary."),
    ("JS003", "Secret in localStorage", Severity.HIGH, "javascript", "Security", check_js_secret_local_storage, "localStorage is readable by injected scripts."),
    ("JS004", "Console log", Severity.LOW, "javascript", "Observability", check_js_console_log, "Production diagnostics should be structured."),
    ("JS005", "dangerouslySetInnerHTML", Severity.HIGH, "javascript", "XSS", check_js_dangerous_react_html, "React raw HTML is a trusted-boundary operation."),
    ("JS006", "document.cookie assignment", Severity.MEDIUM, "javascript", "Session security", check_js_document_cookie_assignment, "Client-written cookies are not HttpOnly."),
    ("JS007", "target blank without rel", Severity.MEDIUM, "javascript", "Browser security", check_js_target_blank_without_rel, "Blank-target links need noopener/noreferrer."),
    ("JS008", "fetch without error boundary", Severity.LOW, "javascript", "Network", check_js_fetch_without_error_boundary, "Network failures need explicit handling."),
)


def build_default_catalog() -> RuleCatalog:
    return RuleCatalog(Rule(*definition) for definition in _RULE_DEFINITIONS)


RULES_BY_ID = {rule.rule_id: rule for rule in build_default_catalog().rules}
