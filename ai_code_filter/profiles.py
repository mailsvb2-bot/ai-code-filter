from __future__ import annotations

import re
from pathlib import Path

from .analyzers.base import Analyzer
from .models import FilePayload, Issue, Severity


_ALLOWED_PROFILES = {"generic", "messaging-bot", "autonomy-canon", "fastapi", "flask", "django", "sqlalchemy"}


def normalize_profiles(raw: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    """Return validated profile names.

    Raises:
        ValueError: when a caller supplies an unknown profile name.
    """
    profiles = tuple(raw or ())
    if not profiles:
        return ("generic",)
    invalid = [profile for profile in profiles if profile not in _ALLOWED_PROFILES]
    if invalid:
        raise ValueError(f"Unknown profile(s): {', '.join(invalid)}")
    return profiles


class ProjectProfileAnalyzer(Analyzer):
    """Project-specific deterministic checks.

    Profiles are intentionally small and rule-like. They do not create a second
    analysis brain; they only add domain sources/sinks that still flow through
    FindingCore for governance, baseline and reporting decisions.
    """

    name = "project_profile"

    def __init__(self, profiles: tuple[str, ...]) -> None:
        self.profiles = tuple(profile for profile in profiles if profile != "generic")

    def analyze(self, payload: FilePayload) -> list[Issue]:
        issues: list[Issue] = []
        if "messaging-bot" in self.profiles:
            issues.extend(_messaging_bot_issues(payload))
        if "autonomy-canon" in self.profiles:
            issues.extend(_autonomy_canon_canon_issues(payload))
        if "fastapi" in self.profiles:
            issues.extend(_fastapi_issues(payload))
        if "flask" in self.profiles:
            issues.extend(_flask_issues(payload))
        if "django" in self.profiles:
            issues.extend(_django_issues(payload))
        if "sqlalchemy" in self.profiles:
            issues.extend(_sqlalchemy_issues(payload))
        return issues


def _lines(payload: FilePayload):
    for idx, line in enumerate(payload.content.splitlines(), start=1):
        yield idx, line


def _messaging_bot_issues(payload: FilePayload) -> list[Issue]:
    issues: list[Issue] = []
    text = payload.content
    rel = payload.relative_path
    lower = text.lower()
    for line_no, line in _lines(payload):
        if re.search(r"(?:bot|messaging)_?token\s*=\s*['\"][0-9]{6,}:[A-Za-z0-9_-]{20,}", line, re.I):
            issues.append(Issue(
                file=rel,
                category="messaging.secret.token_literal",
                severity=Severity.CRITICAL,
                detector="project_profile",
                description="Messaging bot token appears to be hard-coded.",
                recommendation="Move the token to a secret manager or environment variable and rotate it immediately.",
                line_number=line_no,
                location=line.strip(),
                confidence="high",
                evidence={"profile": "messaging-bot", "reason": "token-shaped literal"},
            ))
        if "deletewebhook" in line.lower() and "setwebhook" in lower:
            issues.append(Issue(
                file=rel,
                category="messaging.webhook.lifecycle_mix",
                severity=Severity.MEDIUM,
                detector="project_profile",
                description="Webhook lifecycle calls are mixed in the same project surface; this can hide polling/webhook conflicts.",
                recommendation="Keep webhook setup, deletion and polling fallback behind a single transport configuration contract.",
                line_number=line_no,
                location=line.strip(),
                confidence="medium",
                evidence={"profile": "messaging-bot", "reason": "deleteWebhook and setWebhook both present"},
            ))
        if "create_task(" in line and "aiogram" not in rel.lower():
            issues.append(Issue(
                file=rel,
                category="messaging.async.raw_create_task",
                severity=Severity.MEDIUM,
                detector="project_profile",
                description="Raw asyncio.create_task was found in a Messaging bot profile.",
                recommendation="Route background work through a scheduler/runner abstraction with shutdown and observability semantics.",
                line_number=line_no,
                location=line.strip(),
                confidence="medium",
                evidence={"profile": "messaging-bot", "reason": "raw create_task"},
            ))
    if ("messaging_webhook_secret_token_typo" in lower or "messaging_webhook_secret_token" in lower) and re.search(r"messaging_webhook_secret_token\s*=\s*['\"]?\s*['\"]?", lower):
        issues.append(Issue(
            file=rel,
            category="messaging.webhook.secret_optional",
            severity=Severity.HIGH,
            detector="project_profile",
            description="Webhook secret appears optional or empty under the Messaging bot profile.",
            recommendation="Make webhook secret mandatory outside explicit local development mode.",
            confidence="medium",
            evidence={"profile": "messaging-bot", "reason": "empty webhook secret pattern"},
        ))
    if "callback_query" in lower and "callback_query.answer(" not in lower and "answer_callback_query" not in lower:
        issues.append(Issue(
            file=rel,
            category="messaging.callback_query.missing_answer_signal",
            severity=Severity.MEDIUM,
            detector="project_profile",
            description="Messaging bot callback query handling surface lacks an answer() signal; this can cause stale callback UX/timeouts.",
            recommendation="Ensure callback_query.answer() is called promptly or explicitly document why this handler is not responsible for callback acknowledgement.",
            confidence="low",
            evidence={"profile": "messaging-bot", "reason": "callback_query without answer signal"},
        ))
    if "start_polling" in lower and ("webhook" in lower or "setwebhook" in lower):
        issues.append(Issue(
            file=rel,
            category="messaging.transport.polling_webhook_conflict",
            severity=Severity.HIGH,
            detector="project_profile",
            description="Polling and webhook lifecycle signals appear in the same Messaging bot surface.",
            recommendation="Use one canonical transport resolver so polling and webhook cannot run concurrently for the same bot token.",
            confidence="medium",
            evidence={"profile": "messaging-bot", "reason": "start_polling with webhook terms"},
        ))
    return issues


def _autonomy_canon_canon_issues(payload: FilePayload) -> list[Issue]:
    issues: list[Issue] = []
    rel = payload.relative_path
    text = payload.content
    lower_path = rel.lower()
    lower = text.lower()
    for line_no, line in _lines(payload):
        ll = line.lower()
        if "decision" in ll and ("router" in lower_path or "strategy" in lower_path) and "decisioncore" not in line:
            issues.append(Issue(
                file=rel,
                category="autonomy_canon.second_brain.risk",
                severity=Severity.HIGH,
                detector="project_profile",
                description="Decision-like logic appears outside an explicit DecisionCore surface.",
                recommendation="Route decision selection through the canonical DecisionCore and keep routers/adapters free of decision policy.",
                line_number=line_no,
                location=line.strip(),
                confidence="medium",
                evidence={"profile": "autonomy-canon", "reason": "decision term in router/strategy path"},
            ))
        if re.search(r"\b(requests\.|subprocess\.|os\.system\(|open\()", line) and "effect" not in lower_path and "provider" not in lower_path:
            issues.append(Issue(
                file=rel,
                category="autonomy_canon.raw_effect.risk",
                severity=Severity.HIGH,
                detector="project_profile",
                description="Possible raw side effect outside an effect/provider surface.",
                recommendation="Route side effects through the sealed provider/effect contract with verification and evidence.",
                line_number=line_no,
                location=line.strip(),
                confidence="medium",
                evidence={"profile": "autonomy-canon", "reason": "raw effect call outside provider/effect path"},
            ))
        if "execute" in ll and "verify" not in lower and "evidence" not in lower:
            issues.append(Issue(
                file=rel,
                category="autonomy_canon.execution_without_evidence.risk",
                severity=Severity.MEDIUM,
                detector="project_profile",
                description="Execution surface does not show nearby verification/evidence language.",
                recommendation="Ensure execution flows include verification and evidence/archive emission.",
                line_number=line_no,
                location=line.strip(),
                confidence="low",
                evidence={"profile": "autonomy-canon", "reason": "execute without verification/evidence tokens"},
            ))
    if "sqlite" in lower and ("prod" in lower or "production" in lower):
        issues.append(Issue(
            file=rel,
            category="autonomy_canon.prod_sqlite_fallback",
            severity=Severity.HIGH,
            detector="project_profile",
            description="Production text appears to include a SQLite fallback.",
            recommendation="Use explicit production storage contracts and fail closed when Postgres/runtime storage is unavailable.",
            confidence="medium",
            evidence={"profile": "autonomy-canon", "reason": "sqlite with prod/production"},
        ))
    if ("capability" in lower or "feature" in lower) and "admin" not in lower and "control" not in lower_path:
        issues.append(Issue(
            file=rel,
            category="autonomy_canon.admin_surface.missing_signal",
            severity=Severity.LOW,
            detector="project_profile",
            description="Capability/feature surface lacks nearby admin/control-plane visibility signals.",
            recommendation="Expose feature status, risks and operations through the canonical admin/control-plane surface or document why this is internal-only.",
            confidence="low",
            evidence={"profile": "autonomy-canon", "reason": "capability/feature without admin signal"},
        ))
    return issues



def _fastapi_issues(payload: FilePayload) -> list[Issue]:
    issues: list[Issue] = []
    rel = payload.relative_path
    text = payload.content
    lower = text.lower()
    for line_no, line in _lines(payload):
        ll = line.lower()
        if "htmlresponse" in ll and ('f"' in line or "f'" in line or "request." in ll):
            issues.append(Issue(file=rel, category="fastapi.html_response.dynamic_html", severity=Severity.HIGH, detector="project_profile", description="FastAPI HTMLResponse appears to render dynamic/request data directly.", recommendation="Use templates with escaping or a sanitizer appropriate for HTML output.", line_number=line_no, location=line.strip(), confidence="medium", evidence={"profile": "fastapi", "reason": "HTMLResponse with dynamic/request signal"}))
        if "backgroundtasks" in ll and ".add_task(" in ll and "scheduler" not in lower and "runner" not in lower:
            issues.append(Issue(file=rel, category="fastapi.background_task.raw_add_task", severity=Severity.MEDIUM, detector="project_profile", description="Raw FastAPI BackgroundTasks.add_task was found without scheduler/runner ownership signals.", recommendation="Route background effects through an observed scheduler/runner contract with shutdown and retry semantics.", line_number=line_no, location=line.strip(), confidence="low", evidence={"profile": "fastapi", "reason": "BackgroundTasks.add_task"}))
    return issues


def _flask_issues(payload: FilePayload) -> list[Issue]:
    issues: list[Issue] = []
    rel = payload.relative_path
    for line_no, line in _lines(payload):
        ll = line.lower()
        if "render_template_string(" in ll:
            issues.append(Issue(file=rel, category="flask.render_template_string.risk", severity=Severity.HIGH, detector="project_profile", description="Flask render_template_string can turn user-controlled strings into template execution.", recommendation="Use file-based templates and pass data as context, not as template source.", line_number=line_no, location=line.strip(), confidence="high", evidence={"profile": "flask", "reason": "render_template_string"}))
        if "redirect(" in ll and "request.args" in ll:
            issues.append(Issue(file=rel, category="flask.open_redirect.risk", severity=Severity.HIGH, detector="project_profile", description="Flask redirect appears to use request args directly.", recommendation="Validate redirect targets against an allowlist or use internal endpoint names.", line_number=line_no, location=line.strip(), confidence="medium", evidence={"profile": "flask", "reason": "redirect(request.args)"}))
        if "app.run(" in ll and "debug=true" in ll:
            issues.append(Issue(file=rel, category="flask.debug_true.risk", severity=Severity.HIGH, detector="project_profile", description="Flask debug=True was found.", recommendation="Never enable Flask debug mode outside local development.", line_number=line_no, location=line.strip(), confidence="high", evidence={"profile": "flask", "reason": "debug=True"}))
    return issues


def _django_issues(payload: FilePayload) -> list[Issue]:
    issues: list[Issue] = []
    rel = payload.relative_path
    for line_no, line in _lines(payload):
        ll = line.lower()
        if "mark_safe(" in ll:
            issues.append(Issue(file=rel, category="django.mark_safe.risk", severity=Severity.HIGH, detector="project_profile", description="Django mark_safe disables autoescaping and can create XSS risk.", recommendation="Avoid mark_safe on dynamic data; use escape/format_html with explicit boundaries.", line_number=line_no, location=line.strip(), confidence="high", evidence={"profile": "django", "reason": "mark_safe"}))
        if ".raw(" in ll or "connection.cursor(" in ll:
            issues.append(Issue(file=rel, category="django.raw_sql.review", severity=Severity.MEDIUM, detector="project_profile", description="Django raw SQL surface needs explicit parameterization review.", recommendation="Prefer ORM APIs or parameterized queries with evidence in tests.", line_number=line_no, location=line.strip(), confidence="medium", evidence={"profile": "django", "reason": "raw SQL signal"}))
    return issues


def _sqlalchemy_issues(payload: FilePayload) -> list[Issue]:
    issues: list[Issue] = []
    rel = payload.relative_path
    text = payload.content
    lower = text.lower()
    for line_no, line in _lines(payload):
        ll = line.lower()
        if "text(f" in ll or "text(f'" in ll:
            issues.append(Issue(file=rel, category="sqlalchemy.text.fstring_sql", severity=Severity.HIGH, detector="project_profile", description="SQLAlchemy text() appears to receive an f-string SQL fragment.", recommendation="Use bound parameters instead of formatting values into SQL text.", line_number=line_no, location=line.strip(), confidence="high", evidence={"profile": "sqlalchemy", "reason": "text(f-string)"}))
        if "create_engine(" in ll and "sqlite" in ll and ("prod" in lower or "production" in lower):
            issues.append(Issue(file=rel, category="sqlalchemy.prod_sqlite_engine", severity=Severity.HIGH, detector="project_profile", description="SQLAlchemy production-like config appears to create a SQLite engine.", recommendation="Use explicit Postgres/runtime DB contracts in production and fail closed on missing DSN.", line_number=line_no, location=line.strip(), confidence="medium", evidence={"profile": "sqlalchemy", "reason": "create_engine sqlite prod"}))
    return issues
