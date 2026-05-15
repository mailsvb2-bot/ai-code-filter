from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Iterable

from .rules.catalog import Rule


def load_plugin_rules(plugin_paths: Iterable[str]) -> tuple[list[Rule], list[str]]:
    """Load external rules from Python files exposing register_rules(); returns errors instead of raise exceptions."""
    rules: list[Rule] = []
    errors: list[str] = []
    for raw_path in plugin_paths:
        path = Path(raw_path)
        try:
            spec = importlib.util.spec_from_file_location(f"ai_code_filter_plugin_{path.stem}", path)
            if spec is None or spec.loader is None:
                raise ValueError("could not create import spec")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            register = getattr(module, "register_rules", None)
            if register is None:
                raise ValueError("plugin must expose register_rules()")
            provided = register()
            rules.extend(provided)
        except Exception as exc:
            errors.append(f"{path}: {type(exc).__name__}: {exc}")
    return rules, errors
