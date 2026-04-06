"""IaC Parser Agent — parses Terraform plan JSON into normalized ResourceInventory."""

from __future__ import annotations

import logging
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.enums import ResourceAction
from iac_risk.core.schemas import (
    IaCParserInput,
    IaCParserOutput,
    ResourceChange,
    ResourceInventory,
)

logger = logging.getLogger(__name__)

SUPPORTED_FORMAT_VERSIONS = {"0.1", "0.2", "1.0", "1.1", "1.2"}

# Map Terraform action arrays to our enum
_ACTION_MAP: dict[tuple[str, ...], ResourceAction] = {
    ("create",): ResourceAction.CREATE,
    ("update",): ResourceAction.UPDATE,
    ("delete",): ResourceAction.DELETE,
    ("delete", "create"): ResourceAction.DELETE,  # replace
    ("create", "delete"): ResourceAction.CREATE,  # replace
    ("no-op",): ResourceAction.NO_OP,
    ("read",): ResourceAction.READ,
}


def _parse_action(actions: list[str]) -> ResourceAction:
    key = tuple(actions)
    return _ACTION_MAP.get(key, ResourceAction.NO_OP)


def _extract_module_address(address: str) -> str | None:
    """Extract module address from a full resource address."""
    parts = address.split(".")
    # e.g. "module.vpc.aws_security_group.main" → "module.vpc"
    module_parts: list[str] = []
    i = 0
    while i < len(parts) - 2:
        if parts[i] == "module":
            module_parts.append(f"module.{parts[i + 1]}")
            i += 2
        else:
            break
    return ".".join(module_parts) if module_parts else None


class IaCParserAgent(BaseAgent):
    name = "iac_parser"
    critical = True

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, IaCParserInput):
            return ValidationResult(valid=False, error="Expected IaCParserInput")

        plan = input_data.plan_data
        if not isinstance(plan, dict):
            return ValidationResult(valid=False, error="Plan data must be a dict")

        fmt = plan.get("format_version", "")
        if fmt and fmt not in SUPPORTED_FORMAT_VERSIONS:
            return ValidationResult(
                valid=False,
                error=f"Unsupported format_version '{fmt}'. Supported: {SUPPORTED_FORMAT_VERSIONS}",
            )

        if "resource_changes" not in plan:
            return ValidationResult(valid=False, error="Plan missing 'resource_changes' field")

        return ValidationResult(valid=True)

    def assess(self, input_data: IaCParserInput) -> IaCParserOutput:
        plan = input_data.plan_data
        resources: list[ResourceChange] = []

        for rc in plan.get("resource_changes", []):
            change = rc.get("change", {})
            actions = change.get("actions", ["no-op"])
            action = _parse_action(actions)

            # Skip data sources
            if rc.get("mode") == "data":
                continue

            resource = ResourceChange(
                address=rc.get("address", ""),
                resource_type=rc.get("type", ""),
                provider=rc.get("provider_name", ""),
                action=action,
                before_config=change.get("before"),
                after_config=change.get("after"),
                after_unknown=change.get("after_unknown", {}),
                module_address=_extract_module_address(rc.get("address", "")),
            )
            resources.append(resource)

        inventory = ResourceInventory(
            resources=resources,
            terraform_version=plan.get("terraform_version", ""),
            format_version=plan.get("format_version", ""),
        )

        logger.info(
            "Parsed %d resources from Terraform plan (version %s)",
            len(resources),
            inventory.terraform_version,
        )

        return IaCParserOutput(inventory=inventory)
