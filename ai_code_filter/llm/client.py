from __future__ import annotations

import json
import os
import random
import time
from typing import Any

from ..config import RuntimeConfig
from ..filesystem import split_with_overlap
from ..guards.stereotype import needs_strict_retry
from ..models import FilePayload, Issue, Severity
from .prompts import STRICT_RETRY_SUFFIX, SYSTEM_PROMPT


class LLMReviewUnavailable(RuntimeError):
    pass


class OpenAIReviewClient:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise LLMReviewUnavailable("OPENAI_API_KEY is not set; AI review skipped.")
        try:
            import openai
        except ImportError as exc:
            raise LLMReviewUnavailable("openai package is not installed; AI review skipped.") from exc
        self._openai = openai
        self._client = openai.OpenAI(api_key=api_key, timeout=self.config.http_timeout_seconds, max_retries=0)
        return self._client

    def review(self, payload: FilePayload) -> tuple[str, list[Issue]]:
        chunks = split_with_overlap(payload.content, self.config.chunk_size_chars, self.config.overlap_chars)
        verdict = "APPROVED"
        issues: list[Issue] = []
        for chunk in chunks:
            result = self._call(chunk, strict=False)
            guard_text = " ".join([i.get("description", "") for i in result.get("issues", [])] + [result.get("summary", "")])
            if needs_strict_retry(guard_text):
                result = self._call(chunk, strict=True)
            if result.get("verdict") == "REJECTED":
                verdict = "REJECTED"
            issues.extend(self._parse_issues(payload, result.get("issues", [])))
        return verdict, self._dedupe(issues)

    def _call(self, code: str, strict: bool) -> dict[str, Any]:
        client = self._ensure_client()
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT + ("\n" + STRICT_RETRY_SUFFIX if strict else "")},
            {"role": "user", "content": f"Analyze this code:\n```\n{code}\n```"},
        ]
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                response = client.chat.completions.create(
                    model=self.config.model,
                    messages=messages,
                    temperature=0.0,
                    response_format={"type": "json_object"},
                    timeout=self.config.http_timeout_seconds,
                )
                return json.loads(response.choices[0].message.content)
            except (self._openai.APITimeoutError, self._openai.APIConnectionError, json.JSONDecodeError) as exc:
                last_error = exc
                time.sleep((2 ** attempt) + random.uniform(0, 1))
            except self._openai.APIError as exc:
                raise RuntimeError(f"OpenAI API error: {exc}") from exc
        raise RuntimeError(f"AI review failed after retries: {last_error}")

    def _parse_issues(self, payload: FilePayload, raw_issues: list[dict[str, Any]]) -> list[Issue]:
        parsed: list[Issue] = []
        for raw in raw_issues:
            location = str(raw.get("location", "")).strip() or None
            if location and location not in payload.content:
                continue
            severity_raw = str(raw.get("severity", "MEDIUM")).upper()
            severity = Severity.__members__.get(severity_raw, Severity.MEDIUM)
            parsed.append(Issue(
                file=payload.relative_path,
                category=str(raw.get("category", "AI review")),
                severity=severity,
                detector="ai_review",
                description=str(raw.get("description", "")),
                recommendation=str(raw.get("recommendation", raw.get("description", ""))),
                location=location,
            ))
        return parsed

    def _dedupe(self, issues: list[Issue]) -> list[Issue]:
        seen: set[tuple[str, str, str]] = set()
        unique: list[Issue] = []
        for issue in issues:
            key = (issue.file, issue.category, issue.location or issue.description)
            if key in seen:
                continue
            seen.add(key)
            unique.append(issue)
        return unique
