from __future__ import annotations

CATEGORY_TITLES = {
    "01": "Logical condition errors",
    "02": "Type errors and implicit coercion",
    "03": "Missing None/null/undefined safety",
    "04": "Loop and iteration errors",
    "05": "Async/concurrency errors",
    "06": "Memory/resource leaks",
    "07": "Database errors",
    "08": "API and network errors",
    "09": "Serialization errors",
    "10": "Security vulnerabilities",
    "11": "Architectural violations",
    "12": "Configuration errors",
    "13": "Test errors",
    "14": "CI/CD errors",
    "15": "Hallucinated APIs/libraries",
    "16": "Dependency/version conflicts",
    "17": "API contract violations",
    "18": "Date/time/locale errors",
    "19": "Regex errors",
    "20": "Unsafe eval/exec",
    "21": "Unsafe logging",
    "22": "SRP violations",
    "23": "Mixed business/UI/infrastructure logic",
    "24": "Filesystem errors",
    "25": "Shell script errors",
    "26": "Containerization errors",
    "27": "Missing input validation",
    "28": "Calculation errors",
    "29": "Deprecated/vulnerable libraries",
    "30": "Error handling errors",
    "31": "Ignored return values",
    "32": "Code duplication",
    "33": "Oversized functions/classes",
    "34": "Magic numbers",
    "35": "Tight coupling",
    "36": "Missing edge cases",
    "37": "Float usage for money",
    "38": "Sleep-based synchronization",
    "39": "Unsafe cookies/sessions",
    "40": "Information leakage through headers",
    "41": "Missing security headers",
    "42": "Migration errors",
    "43": "Batch processing without chunking",
    "44": "Forgotten debug hooks",
    "45": "Escaping/encoding errors",
    "46": "Unsuitable data structures",
    "47": "Excessive copying",
    "48": "Character encoding errors",
    "49": "Component interaction errors",
    "50": "Missing monitoring/alerting",
    "51": "Flattery/yes-man review behavior",
    "52": "False claims in comments/names",
}

_BASE_EXAMPLES = (
    "contradictory branch for the same predicate",
    "unreachable branch after return/raise/break",
    "guard checks the wrong variable",
    "condition uses OR where AND is required",
    "condition uses AND where OR is required",
    "missing else for an exhaustive state machine",
    "negated condition makes branch impossible",
    "state transition skips required validation",
    "caller assumes success without checking result",
    "default value changes behavior silently",
    "mutable state shared across requests",
    "side effect happens before authorization",
    "exception path loses original cause",
    "cleanup path does not run on error",
    "function name promises behavior not implemented",
    "comment promises a safety check absent in code",
    "test asserts implementation detail instead of contract",
    "configuration fallback masks production misconfiguration",
    "integration declared by registry but no executable adapter exists",
    "report says approved while analyzer skipped the file",
)

_CATEGORY_SPECIFIC = {
    "01": ("a > b and a < b", "assignment-like condition", "always true comparison", "empty branch hides error", "wrong operator precedence"),
    "02": ("string compared to number", "bool parsed from non-empty string", "float used for cents", "implicit json type assumption", "None treated as sequence"),
    "03": ("optional value dereferenced", "null response body not checked", "dict key assumed present", "undefined JS property chained", "nullable DB column assumed non-null"),
    "04": ("off-by-one loop", "collection mutated during iteration", "iterator consumed twice", "break exits wrong loop", "pagination token not advanced"),
    "05": ("blocking call in async function", "unawaited coroutine", "fire-and-forget task without owner", "race on shared cache", "missing lock around shared state"),
    "06": ("file handle not closed", "network response not closed", "cursor not closed", "unbounded cache", "temporary file never removed"),
    "07": ("SQL string interpolation", "transaction opened without rollback", "missing idempotency key", "N+1 query loop", "unsafe migration DDL at runtime"),
    "08": ("HTTP request without timeout", "response status ignored", "retry without backoff", "TLS verification disabled", "API error body ignored"),
    "09": ("pickle on untrusted input", "json schema not validated", "lossy datetime serialization", "binary/text mode mismatch", "unknown enum silently accepted"),
    "10": ("hardcoded secret", "XSS sink", "command injection", "path traversal", "insecure random token"),
    "11": ("god object", "second decision brain", "infrastructure bypass", "hidden policy branch", "raw side effect outside sealed adapter"),
    "12": ("DEBUG enabled", "missing required env var", "unsafe default credential", "prod uses local fallback", "config duplicated across modules"),
    "13": ("test has no assertion", "xfail masks failure", "mock asserts wrong contract", "flaky sleep test", "golden output not checked"),
    "14": ("CI skips security gate", "workflow only runs on docs", "artifact includes secrets", "release gate missing tests", "lint result ignored"),
    "15": ("method does not exist", "library name hallucinated", "wrong SDK namespace", "async method called sync", "attribute missing from imported module"),
    "16": ("unpinned major dependency", "incompatible package versions", "lockfile drift", "runtime version mismatch", "deprecated API version"),
    "17": ("removed argument", "return type changed", "caller passes obsolete keyword", "status enum changed", "API response shape changed"),
    "18": ("naive datetime", "timezone ignored", "DST unsafe math", "locale-dependent parse", "date compared as string"),
    "19": ("catastrophic backtracking", "unescaped user pattern", "wrong capture group", "multiline flag missing", "regex matches empty string forever"),
    "20": ("eval on user input", "exec dynamic code", "Function constructor", "setTimeout string code", "template compiled from unsafe source"),
    "21": ("secret in log", "PII in exception", "token printed", "full request body logged", "stack trace exposed to user"),
    "22": ("function validates, persists and renders", "class owns multiple bounded contexts", "CLI contains business logic", "policy mixed with transport", "report writer mutates analysis state"),
    "23": ("UI callback updates database directly", "template decides business policy", "controller builds SQL", "adapter computes reward", "config branch contains product logic"),
    "24": ("path traversal", "relative path assumes cwd", "encoding omitted", "atomic write missing", "directory not created before write"),
    "25": ("unquoted variable", "set -e missing", "pipe failure ignored", "rm uses unchecked variable", "curl result ignored"),
    "26": ("root container user", "secret baked into image", "missing healthcheck", "cache copied into image", "runtime writes to read-only path"),
    "27": ("request body trusted", "amount not validated", "email not normalized", "enum not checked", "file extension trusted"),
    "28": ("integer division mistake", "rounding before aggregation", "overflow risk", "currency precision loss", "negative value not handled"),
    "29": ("deprecated crypto", "EOL framework", "known vulnerable package", "old TLS version", "unsupported runtime"),
    "30": ("bare except", "except pass", "error converted to success", "retry hides permanent failure", "exception swallowed without audit"),
    "31": ("subprocess returncode ignored", "database execute result ignored", "delete result unchecked", "write result unchecked", "future result never observed"),
    "32": ("copy-pasted resolver", "duplicated config parser", "same regex in multiple files", "duplicate adapter logic", "parallel implementations diverge"),
    "33": ("god function", "large class with unrelated methods", "deep nested function", "long method hides branches", "single file owns whole pipeline"),
    "34": ("timeout literal", "port literal", "risk threshold literal", "retry count literal", "currency multiplier literal"),
    "35": ("module imports concrete adapter", "service depends on UI", "domain depends on database", "circular import", "global singleton dependency"),
    "36": ("empty input not tested", "zero amount not handled", "negative amount not handled", "large batch not chunked", "duplicate event not idempotent"),
    "37": ("price as float", "fee as float", "balance as float", "tax as float", "discount as float"),
    "38": ("sleep waits for task", "sleep waits for network", "sleep in test sync", "sleep in retry loop", "sleep blocks event loop"),
    "39": ("cookie lacks HttpOnly", "cookie lacks Secure", "SameSite missing", "session id predictable", "session not rotated"),
    "40": ("server header leaks stack", "debug header exposes version", "error response exposes path", "CORS exposes credentials", "trace id leaks tenant data"),
    "41": ("CSP missing", "HSTS missing", "X-Frame-Options missing", "X-Content-Type-Options missing", "Referrer-Policy missing"),
    "42": ("migration not idempotent", "DDL during request", "down migration destructive", "schema version not tracked", "data migration lacks rollback"),
    "43": ("loads all rows", "sends all emails at once", "no pagination", "batch lacks backpressure", "memory grows with input size"),
    "44": ("pdb breakpoint", "console.log debug", "print secret", "debug endpoint", "temporary feature flag"),
    "45": ("HTML not escaped", "SQL not parameterized", "shell args not quoted", "URL not encoded", "CSV injection not handled"),
    "46": ("list used for membership hot path", "dict order assumed", "global list as queue", "set used where order required", "nested list where index needed"),
    "47": ("deepcopy in loop", "whole file read for streaming task", "large payload duplicated", "json dumped twice", "temporary list from generator"),
    "48": ("encoding omitted", "bytes decoded implicitly", "latin1 assumed", "newline mode wrong", "BOM not handled"),
    "49": ("producer event not consumed", "consumer expects different schema", "adapter returns wrong status", "component bypasses policy", "contract mismatch between services"),
    "50": ("no audit log", "no alert on failed execution", "no metric for rejected action", "no trace id", "no health/readiness probe"),
    "51": ("review agrees with impossible claim", "approval without evidence", "vague praise instead of defect", "user preference overrides safety", "model accepts false premise"),
    "52": ("final production claim not backed by code", "README says integrated but registry only", "comment says validated but no validation", "function name says safe but sink unsafe", "capability declared without implementation"),
}


def _generate_error_catalog() -> str:
    lines: list[str] = []
    total = 0
    for number in sorted(CATEGORY_TITLES):
        title = CATEGORY_TITLES[number]
        examples = list(_CATEGORY_SPECIFIC[number]) + [f"{base} [{title}]" for base in _BASE_EXAMPLES]
        lines.append(f"{number}. {title}")
        for index, example in enumerate(examples[:20], 1):
            total += 1
            lines.append(f"  {number}.{index:02d} {example}")
    lines.append(f"TOTAL_EXAMPLES: {total}")
    return "\n".join(lines)

ERROR_CATALOG = _generate_error_catalog()

SYSTEM_PROMPT = f"""
You are a strict code auditor. Analyze only the provided code. Return strict JSON.
Do not claim patterns exist unless the exact location is present in the code.
Every issue must include category, severity, description, recommendation and location.
The location must be an exact source-code snippet from the analyzed chunk.
The recommendation must be concrete and directly actionable.
Allowed severities: CRITICAL, HIGH, MEDIUM, LOW.
If no issues are present, return {{"verdict":"APPROVED","issues":[],"summary":"No issues."}}.

Catalog: 52 categories with 1000+ concrete example situations.
{ERROR_CATALOG}

JSON schema:
{{
  "verdict": "APPROVED | REJECTED",
  "issues": [
    {{"category":"...", "severity":"CRITICAL|HIGH|MEDIUM|LOW", "description":"...", "recommendation":"...", "location":"exact code snippet"}}
  ],
  "summary":"..."
}}
""".strip()

STRICT_RETRY_SUFFIX = """
Previous response was rejected by the style guard. Re-analyze with only concrete, located defects.
No vague wording. No flattery. No general advice without a matching location.
Each finding must include a precise fix in recommendation.
""".strip()
