"""Cloud Misconfiguration Agent — detects misconfigurations using Prowler check catalog."""

from __future__ import annotations

import logging
import re
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.enums import DetectionOperator, Severity
from iac_risk.core.schemas import (
    CloudMisconfigInput,
    CloudMisconfigOutput,
    Finding,
    ProwlerCheckDef,
    ResourceChange,
    ResourceInventory,
)
from iac_risk.services.prowler_catalog import ProwlerCatalog

logger = logging.getLogger(__name__)


def _resolve_field_path(config: dict[str, Any] | None, path: str) -> Any:
    """Navigate a dot-separated field path into a nested dict.

    Supports numeric indices for list access: "rule.0.apply_server_side_encryption"
    """
    if config is None:
        return None
    current: Any = config
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                idx = int(part)
                current = current[idx] if idx < len(current) else None
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _is_field_unknown(resource: ResourceChange, field_path: str) -> bool:
    """Check if a field is in after_unknown (not yet computed at plan time)."""
    val = _resolve_field_path(resource.after_unknown, field_path)
    return val is True


def _find_sub_resource(
    inventory: ResourceInventory,
    parent: ResourceChange,
    sub_resource_type: str,
    link_field: str,
) -> ResourceChange | None:
    """Find a sub-resource that references the parent resource."""
    parent_name = None
    if parent.after_config:
        parent_name = parent.after_config.get("bucket") or parent.after_config.get("id")
    parent_address_name = parent.address.split(".")[-1] if "." in parent.address else parent.address

    for resource in inventory.resources:
        if resource.resource_type != sub_resource_type:
            continue
        if resource.after_config is None:
            continue

        # Match by link field value (e.g., bucket name)
        link_value = resource.after_config.get(link_field)
        if link_value and parent_name and link_value == parent_name:
            return resource

        # Match by address naming convention (e.g., same logical name)
        sub_name = resource.address.split(".")[-1] if "." in resource.address else ""
        if sub_name == parent_address_name:
            return resource

    return None


def _check_contains(actual: Any, expected: Any) -> bool:
    """Check if actual contains the expected value (for list/string checks)."""
    if isinstance(actual, list) and isinstance(expected, dict):
        for item in actual:
            if isinstance(item, dict):
                if all(
                    item.get(k) == v or (isinstance(v, list) and item.get(k) == v)
                    for k, v in expected.items()
                ):
                    return True
    if isinstance(actual, str) and isinstance(expected, str):
        return expected in actual
    return False


def _matches_expected(actual: Any, operator: DetectionOperator, expected: Any) -> bool:
    """Evaluate whether actual value matches expected using the operator."""
    if operator == DetectionOperator.EQUALS:
        # Treat None as False for boolean checks
        if actual is None and expected is True:
            return False
        if actual is None and expected is False:
            return True
        return actual == expected
    if operator == DetectionOperator.NOT_EQUALS:
        return actual != expected
    if operator == DetectionOperator.EXISTS:
        return actual is not None
    if operator == DetectionOperator.NOT_EXISTS:
        return actual is None
    if operator == DetectionOperator.CONTAINS:
        return _check_contains(actual, expected)
    if operator == DetectionOperator.NOT_CONTAINS:
        return not _check_contains(actual, expected)
    if operator == DetectionOperator.REGEX_MATCH:
        if isinstance(actual, str) and isinstance(expected, str):
            return bool(re.search(expected, actual))
        return False
    if operator == DetectionOperator.GREATER_THAN:
        try:
            a = float(actual) if actual is not None else 0
            return a > float(expected)
        except (TypeError, ValueError):
            return False
    if operator == DetectionOperator.LESS_THAN:
        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False
    return False


def evaluate_check(
    check: ProwlerCheckDef,
    resource: ResourceChange,
    inventory: ResourceInventory,
) -> Finding | None:
    """Evaluate a single check against a resource. Returns Finding if check fails."""
    dl = check.detection_logic

    # Try sub-resource pattern first (modern AWS provider)
    if dl.sub_resource_type:
        sub = _find_sub_resource(
            inventory, resource, dl.sub_resource_type, dl.sub_resource_link_field,
        )
        if sub:
            actual = _resolve_field_path(sub.after_config, dl.field_path)
        else:
            # Sub-resource not present — try legacy path on parent
            if dl.legacy_field_path:
                actual = _resolve_field_path(resource.after_config, dl.legacy_field_path)
                if actual is not None:
                    expected = (
                        dl.legacy_expected_value
                        if dl.legacy_expected_value is not None
                        else dl.expected_value
                    )
                    if _matches_expected(actual, dl.operator, expected):
                        return None  # check passes
                    return _make_finding(check, resource, actual, expected)
            # No sub-resource and no legacy path → feature not configured
            actual = None
    else:
        actual = _resolve_field_path(resource.after_config, dl.field_path)

    # Check if value is unknown at plan time
    if _is_field_unknown(resource, dl.field_path):
        return Finding(
            check_id=check.check_id,
            resource_address=resource.address,
            resource_type=resource.resource_type,
            severity=Severity.INFORMATIONAL,
            title=check.title,
            description=f"{check.description} (value unknown at plan time)",
            actual_value="<unknown>",
            expected_value=dl.expected_value,
            remediation=check.remediation,
            compliance_controls=_flatten_compliance_controls(
                check.compliance_mappings,
            ),
            attack_scenarios=check.attack_scenarios,
        )

    if _matches_expected(actual, dl.operator, dl.expected_value):
        return None  # check passes

    return _make_finding(check, resource, actual, dl.expected_value)


def _flatten_compliance_controls(
    mappings: dict[str, list[str]],
) -> list[str]:
    """Flatten compliance mappings into a single list of control IDs."""
    controls: list[str] = []
    for framework, ctrl_ids in sorted(mappings.items()):
        for ctrl_id in ctrl_ids:
            controls.append(f"{framework}:{ctrl_id}")
    return controls


def _make_finding(
    check: ProwlerCheckDef,
    resource: ResourceChange,
    actual: Any,
    expected: Any,
) -> Finding:
    return Finding(
        check_id=check.check_id,
        resource_address=resource.address,
        resource_type=resource.resource_type,
        severity=check.severity,
        title=check.title,
        description=check.description,
        actual_value=actual,
        expected_value=expected,
        remediation=check.remediation,
        compliance_controls=_flatten_compliance_controls(
            check.compliance_mappings,
        ),
        attack_scenarios=check.attack_scenarios,
    )


class CloudMisconfigAgent(BaseAgent):
    name = "cloud_misconfig"
    critical = True

    def __init__(self, catalog: ProwlerCatalog | None = None) -> None:
        self.catalog = catalog or ProwlerCatalog()

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, CloudMisconfigInput):
            return ValidationResult(valid=False, error="Expected CloudMisconfigInput")
        return ValidationResult(valid=True)

    def assess(self, input_data: CloudMisconfigInput) -> CloudMisconfigOutput:
        inventory = input_data.inventory
        findings: list[Finding] = []

        for resource in inventory.resources:
            checks = self.catalog.get_checks_for_resource_type(resource.resource_type)
            for check in checks:
                finding = evaluate_check(check, resource, inventory)
                if finding is not None:
                    findings.append(finding)

        logger.info(
            "Cloud misconfiguration scan complete: %d findings from %d resources",
            len(findings),
            len(inventory.resources),
        )

        return CloudMisconfigOutput(findings=findings)
