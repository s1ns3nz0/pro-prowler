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


_CONFIG_TRAITS: dict[str, list[str]] = {
    "aws_s3_bucket": ["bucket", "force_destroy"],
    "aws_s3_bucket_versioning": ["status"],
    "aws_s3_bucket_server_side_encryption_configuration": [],
    "aws_s3_bucket_public_access_block": [
        "block_public_acls", "block_public_policy",
    ],
    "aws_db_instance": [
        "engine", "engine_version", "instance_class",
        "allocated_storage", "storage_encrypted", "multi_az",
        "deletion_protection", "backup_retention_period",
    ],
    "aws_instance": [
        "instance_type", "ami",
        "monitoring", "ebs_optimized",
    ],
    "aws_lb": ["internal", "load_balancer_type"],
    "aws_lb_listener": ["port", "protocol"],
    "aws_lb_target_group": [
        "port", "protocol", "target_type",
    ],
    "aws_security_group": ["name", "description"],
    "aws_vpc": ["cidr_block", "enable_dns_support"],
    "aws_subnet": ["cidr_block", "availability_zone", "map_public_ip_on_launch"],
    "aws_ecs_cluster": ["name"],
    "aws_ecs_service": ["name", "launch_type", "desired_count"],
    "aws_ecs_task_definition": [
        "family", "cpu", "memory", "network_mode",
    ],
    "aws_ecr_repository": ["name", "image_tag_mutability"],
    "aws_iam_role": ["name"],
    "aws_iam_policy": ["name"],
    "aws_lambda_function": [
        "function_name", "runtime", "memory_size", "timeout",
    ],
    "aws_cloudwatch_log_group": ["name", "retention_in_days"],
    "aws_kms_key": ["description", "key_usage"],
    "aws_secretsmanager_secret": ["name"],
    "aws_dynamodb_table": [
        "name", "billing_mode", "hash_key",
    ],
    "aws_sqs_queue": ["name"],
    "aws_sns_topic": ["name"],
    "aws_cloudfront_distribution": ["enabled"],
    "aws_route_table": [],
    "aws_internet_gateway": [],
    "aws_nat_gateway": [],
    "aws_eip": [],
    "aws_route_table_association": [],
    "aws_db_subnet_group": ["name"],
}


def _build_config_summary(
    resource_type: str, after_config: dict[str, Any] | None,
) -> str:
    """Extract key config traits into a human-readable summary."""
    if not after_config:
        return ""
    traits = _CONFIG_TRAITS.get(resource_type)
    if traits is None:
        # Unknown type — pick first few non-null scalar values
        traits = list(after_config.keys())[:4]
    if not traits:
        return ""
    parts: list[str] = []
    for key in traits:
        val = after_config.get(key)
        if val is None or val == {} or val == []:
            continue
        if isinstance(val, (dict, list)):
            continue
        # Clean up key name for display
        label = key.replace("_", " ").title()
        parts.append(f"{label}: {val}")
    return ", ".join(parts)


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

            rtype = rc.get("type", "")
            after = change.get("after")
            resource = ResourceChange(
                address=rc.get("address", ""),
                resource_type=rtype,
                provider=rc.get("provider_name", ""),
                action=action,
                before_config=change.get("before"),
                after_config=after,
                after_unknown=change.get("after_unknown", {}),
                module_address=_extract_module_address(
                    rc.get("address", ""),
                ),
                config_summary=_build_config_summary(rtype, after),
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
