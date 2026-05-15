"""Assistant-grade orchestration helpers for code audit outputs.

These helpers are deterministic. They do not expose hidden reasoning and they do not
perform network access. They convert scan data into auditable plans, evidence maps,
and patch queues that can be reviewed in CI or by a human maintainer.
"""

from .capabilities import assistant_capability_matrix
from .report_explainer import explain_report
from .review_plan import build_review_plan
from .patch_plan import build_patch_plan

__all__ = [
    "assistant_capability_matrix",
    "build_patch_plan",
    "build_review_plan",
    "explain_report",
]
