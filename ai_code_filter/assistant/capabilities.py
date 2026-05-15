from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ai_code_filter import __version__


@dataclass(frozen=True)
class AssistantCapability:
    id: str
    name: str
    status: str
    boundary: str
    output: str


def assistant_capability_matrix() -> dict[str, Any]:
    """Return deterministic assistant-like capabilities available in the tool.

    The matrix is explicit so the project never claims invisible abilities. Anything
    that requires online access, private context, or model reasoning is represented as
    an adapter boundary rather than as a built-in fact source.
    """

    capabilities = [
        AssistantCapability("AC001", "Closure map", "implemented", "Derived from issue severity, detector, and file distribution.", "P0/P1/P2 queues, stop condition, maturity score."),
        AssistantCapability("AC002", "Evidence ledger", "implemented", "Uses scan results, failed files, skipped files, and explicit report metadata only.", "facts, assumptions, risks, verification steps."),
        AssistantCapability("AC003", "Patch plan generator", "implemented", "Creates reviewable remediation steps; it does not rewrite source files automatically.", "ordered patch queue with owners, risk notes, and validation commands."),
        AssistantCapability("AC004", "Report explainer", "implemented", "Summarizes native JSON reports without adding unsupported findings.", "Markdown or JSON executive summary."),
        AssistantCapability("AC005", "Prompt pack", "implemented", "Provides reusable review prompts; external LLM execution remains optional.", "strict reviewer, patch reviewer, release gate prompts."),
        AssistantCapability("AC006", "External research adapter", "adapter-only", "No network access is built in. Connectors can pass cited evidence into the ledger.", "source records with title, locator, quote, and confidence."),
        AssistantCapability("AC007", "Type/tool adapter coordination", "implemented", "Delegates to installed tools such as pyright or mypy when present.", "typed diagnostics converted to UnifiedReport issues."),
    ]
    return {
        "version": __version__,
        "capabilities": [asdict(item) for item in capabilities],
        "non_goals": [
            "No hidden chain-of-thought export.",
            "No network browsing inside the package.",
            "No automatic code modification without an explicit external patching layer.",
            "No claim that optional adapters ran when they were skipped.",
        ],
    }
