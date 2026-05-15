from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .config import BINARY_EXTENSIONS, DEFAULT_IGNORED_DIRS


def validate_text_file(path: Path, max_bytes: int = 2_000_000) -> str:
    """Return UTF-8 file content. Raises ValueError for binary, empty, or oversized files."""
    if path.suffix.lower() in BINARY_EXTENSIONS:
        raise ValueError(f"Binary file skipped: {path}")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds max size {max_bytes} bytes: {path}")
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        raise ValueError(f"Empty file: {path}")
    return content


def _is_ignored(path: Path, ignored_dirs: set[str]) -> bool:
    return any(part in ignored_dirs for part in path.parts)


def collect_files(paths: Iterable[str], extensions: Iterable[str]) -> list[Path]:
    allowed = tuple(ext.lower() for ext in extensions)
    ignored = set(DEFAULT_IGNORED_DIRS)
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_file() and path.suffix.lower() in allowed and not _is_ignored(path, ignored):
            files.append(path)
        elif path.is_dir():
            for candidate in path.rglob("*"):
                if candidate.is_file() and candidate.suffix.lower() in allowed and not _is_ignored(candidate.relative_to(path), ignored):
                    files.append(candidate)
    return sorted(set(files))


def infer_project_root(paths: Iterable[str]) -> Path:
    first = Path(next(iter(paths), ".")).resolve()
    return first.parent if first.is_file() else first


def split_with_overlap(text: str, chunk_size: int, overlap: int) -> list[str]:
    """Split text into overlapping chunks. Raises ValueError when overlap is invalid."""
    if chunk_size <= overlap:
        raise ValueError("chunk_size must be larger than overlap")
    if len(text) <= chunk_size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        start = end - overlap if end < len(text) else len(text)
    return chunks
