"""Terraform plan JSON parser — pluggable implementation."""

from __future__ import annotations

import logging
from typing import Any

from iac_risk.agents.parsers.base_parser import BaseIaCParser
from iac_risk.core.enums import ResourceAction
from iac_risk.core.schemas import ResourceChange, ResourceInventory

logger = logging.getLogger(__name__)

SUPPORTED_FORMAT_VERSIONS = {"0.1", "0.2", "1.0", "1.1", "1.2"}

_ACTION_MAP: dict[tuple[str, ...], ResourceAction] = {
    ("create",): ResourceAction.CREATE,
    ("update",): ResourceAction.UPDATE,
    ("delete",): ResourceAction.DELETE,
    ("delete", "create"): ResourceAction.DELETE,
    ("create", "delete"): ResourceAction.CREATE,
    ("no-op",): ResourceAction.NO_OP,
    ("read",): ResourceAction.READ,
}


def _parse_action(actions: list[str]) -> ResourceAction:
    return _ACTION_MAP.get(tuple(actions), ResourceAction.NO_OP)


def _extract_module_address(address: str) -> str | None:
    parts = address.split(".")
    module_parts: list[str] = []
    i = 0
    while i < len(parts) - 2:
        if parts[i] == "module":
            module_parts.append(f"module.{parts[i + 1]}")
            i += 2
        else:
            break
    return ".".join(module_parts) if module_parts else None


class TerraformPlanParser(BaseIaCParser):
    """Parses Terraform plan JSON output."""

    name = "terraform"
    supported_extensions = [".tf", ".tf.json"]

    def can_parse(self, data: dict[str, Any]) -> bool:
        fmt = data.get("format_version", "")
        return (
            "resource_changes" in data
            and (not fmt or fmt in SUPPORTED_FORMAT_VERSIONS)
        )

    def parse(self, data: dict[str, Any]) -> ResourceInventory:
        resources: list[ResourceChange] = []

        for rc in data.get("resource_changes", []):
            change = rc.get("change", {})
            actions = change.get("actions", ["no-op"])
            action = _parse_action(actions)

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
                module_address=_extract_module_address(
                    rc.get("address", ""),
                ),
            )
            resources.append(resource)

        inventory = ResourceInventory(
            resources=resources,
            terraform_version=data.get("terraform_version", ""),
            format_version=data.get("format_version", ""),
        )

        logger.info(
            "Terraform parser: %d resources (version %s)",
            len(resources),
            inventory.terraform_version,
        )

        return inventory
