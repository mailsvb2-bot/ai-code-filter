from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_native_report(path: str | Path) -> dict[str, Any]:
    """Load a native report JSON object.

    Raises ValueError when the file is not a native AI Code Filter report.
    JSON decoding and file-system errors are intentionally propagated to the caller.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Native report must be a JSON object.")
    if "issues" not in data or not isinstance(data["issues"], list):
        raise ValueError("Native report must contain an issues list.")
    return data


def _ensure_parent(path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    return out


def write_json(path: str | Path | None, data: dict[str, Any]) -> None:
    if path:
        _ensure_parent(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text(path: str | Path | None, text: str) -> None:
    if path:
        _ensure_parent(path).write_text(text, encoding="utf-8")
