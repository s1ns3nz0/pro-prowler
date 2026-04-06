"""Pluggable IaC parser interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from iac_risk.core.schemas import ResourceInventory


class BaseIaCParser(ABC):
    """Abstract base class for IaC parsers.

    Each IaC tool (Terraform, CloudFormation, Pulumi) gets its own
    parser implementation. All parsers produce a ResourceInventory.
    """

    name: str = "base"
    supported_extensions: list[str] = []

    @abstractmethod
    def can_parse(self, data: dict[str, Any]) -> bool:
        """Check if this parser can handle the given input data."""
        ...

    @abstractmethod
    def parse(self, data: dict[str, Any]) -> ResourceInventory:
        """Parse input data into a ResourceInventory."""
        ...
