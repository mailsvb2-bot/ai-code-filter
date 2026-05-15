from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class EvidenceRecord:
    kind: str
    statement: str
    source: str
    confidence: str


def evidence_to_dict(records: Iterable[EvidenceRecord]) -> list[dict[str, Any]]:
    return [asdict(record) for record in records]
