from __future__ import annotations

from typing import Any


def prompt_pack() -> dict[str, Any]:
    """Return reusable prompts for optional external LLM review.

    The package stores prompts as data. Execution is outside this module so reports can
    distinguish deterministic findings from optional model-assisted commentary.
    """

    return {
        "strict_code_reviewer": {
            "purpose": "Find concrete code defects only from supplied snippets.",
            "rules": [
                "Use exact locations from the provided code.",
                "Separate facts from assumptions.",
                "Do not claim a dependency method is missing without tool or SDK evidence.",
                "Return structured JSON with severity and remediation.",
            ],
        },
        "patch_reviewer": {
            "purpose": "Review a proposed patch against existing findings.",
            "rules": [
                "Check whether the patch removes the root cause.",
                "Check regression tests and compatibility.",
                "Call out skipped verification explicitly.",
            ],
        },
        "release_gate": {
            "purpose": "Summarize whether a release can proceed.",
            "rules": [
                "Block on CRITICAL/HIGH unless explicitly suppressed with governance.",
                "Block on failed files.",
                "Treat skipped type tools as accepted risk, not as success.",
            ],
        },
    }
