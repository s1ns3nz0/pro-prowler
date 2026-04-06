"""Thread-safe pipeline context for sharing data between agents."""

from __future__ import annotations

import threading
from typing import Any

from iac_risk.core.schemas import AgentResult


class PipelineContext:
    """Thread-safe shared state for the assessment pipeline."""

    def __init__(self) -> None:
        self._results: dict[str, AgentResult] = {}
        self._lock = threading.Lock()

    def set_result(self, agent_name: str, result: AgentResult) -> None:
        with self._lock:
            self._results[agent_name] = result

    def get_result(self, agent_name: str) -> AgentResult | None:
        with self._lock:
            return self._results.get(agent_name)

    def get_output(self, agent_name: str) -> Any:
        with self._lock:
            result = self._results.get(agent_name)
            if result is None:
                return None
            return result.output

    @property
    def all_results(self) -> dict[str, AgentResult]:
        with self._lock:
            return dict(self._results)
