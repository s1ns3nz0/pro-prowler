"""Base agent abstract class defining the agent contract."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from iac_risk.core.enums import AgentStatus
from iac_risk.core.schemas import AgentResult

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    valid: bool
    error: str = ""


class BaseAgent(ABC):
    """Abstract base class for all assessment agents.

    Every agent implements:
    - validate_input: check input before processing
    - assess: run the assessment logic
    """

    name: str = "base"
    critical: bool = True  # If True, failure stops the pipeline

    @abstractmethod
    def validate_input(self, input_data: Any) -> ValidationResult:
        ...

    @abstractmethod
    def assess(self, input_data: Any) -> Any:
        ...

    def run(self, input_data: Any) -> AgentResult:
        """Template method: validate → assess → wrap in AgentResult."""
        start = time.monotonic()
        try:
            validation = self.validate_input(input_data)
            if not validation.valid:
                logger.error("Agent '%s' input validation failed: %s", self.name, validation.error)
                return AgentResult(
                    agent_name=self.name,
                    status=AgentStatus.FAILED,
                    error=validation.error,
                    duration_ms=int((time.monotonic() - start) * 1000),
                )

            output = self.assess(input_data)

            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.COMPLETED,
                output=output,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except Exception as e:
            logger.exception("Agent '%s' failed with exception", self.name)
            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_ms=int((time.monotonic() - start) * 1000),
            )
