from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


DEFAULT_EXTENSIONS = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".go", ".rs", ".rb", ".php")
DEFAULT_IGNORED_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv", "node_modules", "dist", "build", ".ai-code-filter"}
BINARY_EXTENSIONS = {".pyc", ".so", ".dll", ".exe", ".bin", ".zip", ".tar", ".gz", ".png", ".jpg", ".jpeg", ".pdf"}
DEFAULT_MODEL = "gpt-4o"


@dataclass(frozen=True)
class RuntimeConfig:
    model: str = DEFAULT_MODEL
    chunk_size_chars: int = 20_000
    overlap_chars: int = 500
    max_retries: int = 3
    http_timeout_seconds: int = 120
    extensions: tuple[str, ...] = DEFAULT_EXTENSIONS
    state_dir_name: str = ".ai-code-filter"
    enable_ai_review: bool = True
    enable_drift: bool = True
    plugin_paths: tuple[str, ...] = ()
    workers: int = 1
    enable_type_tools: bool = False
    enable_sdk_index: bool = False
    enable_sdk_imports: bool = False
    enable_unknown_call_check: bool = False
    sdk_index_output: str | None = None
    profiles: tuple[str, ...] = ("generic",)

    def state_dir(self, project_root: Path) -> Path:
        return project_root / self.state_dir_name
