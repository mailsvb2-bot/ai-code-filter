from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import FilePayload, Issue


class Analyzer(ABC):
    name: str

    @abstractmethod
    def analyze(self, payload: FilePayload) -> list[Issue]:
        """Return issues for one file. Raises NotImplementedError in abstract analyzer base classes."""
        raise NotImplementedError
