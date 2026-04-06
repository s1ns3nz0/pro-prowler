"""Change Management Agent — compliance impact assessment + gate recommendation."""

from __future__ import annotations

import logging
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.enums import GateRecommendation
from iac_risk.core.schemas import (
    ChangeManagementInput,
    ChangeManagementOutput,
    ChangeRiskEntry,
    ComplianceGapAnalysis,
    Finding,
    ResourceChange,
    RiskAcceptanceRecord,
)

logger = logging.getLogger(__name__)

# Controls that trigger BLOCK when gapped
_BLOCK_CONTROLS: set[str] = {
    # PCI-DSS
    "PCI_DSS:6.5.1", "PCI_DSS:7.1.1", "PCI_DSS:7.2",
    "PCI_DSS:10.3.2", "PCI_DSS:10.5.1",
    # ISO 27001
    "ISO_27001:A.8.24", "ISO_27001:A.8.32",
    "ISO_27001:A.10.1.1",
    # ISO 27701
    "ISO_27701:A.7.4.5", "ISO_27701:B.8.4.2",
    # GDPR
    "GDPR:Art.25", "GDPR:Art.32", "GDPR:Art.44",
    # SOC 2
    "SOC_2:CC6.1", "SOC_2:CC6.6", "SOC_2:CC6.7",
    "SOC_2:CC7.2", "SOC_2:CC8.1", "SOC_2:A1.3",
}

# Controls that trigger WARN
_WARN_CONTROLS: set[str] = {
    "GDPR:Art.30", "GDPR:Art.35",
    "ISO_27001:A.8.8", "ISO_27001:A.8.9",
    "ISO_27001:A.8.20", "ISO_27001:A.8.21",
}

# Severity-based risk of change
_SEVERITY_RISK: dict[str, str] = {
    "CRITICAL": "high",
    "HIGH": "high",
    "MODERATE": "medium",
    "LOW": "low",
    "INFORMATIONAL": "low",
}


def _generate_rollback_steps(
    resource: ResourceChange,
) -> list[str]:
    """Generate rollback steps for a resource change."""
    action = resource.action.value if hasattr(resource.action, "value") else str(resource.action)
    addr = resource.address
    rtype = resource.resource_type

    if action == "create":
        return [
            f"Run: terraform destroy -target={addr}",
            f"Verify {rtype} resource is removed",
            "Confirm no dependent resources are affected",
        ]
    if action == "update":
        return [
            f"Revert the Terraform configuration for {addr}",
            "Run: terraform plan to verify rollback diff",
            "Run: terraform apply to restore previous state",
            f"Verify {rtype} attributes match pre-change values",
        ]
    if action == "delete":
        return [
            f"Restore {addr} from Terraform state backup",
            "Re-import the resource if state backup unavailable",
            f"Verify {rtype} resource is operational",
        ]
    return [f"Review and manually revert changes to {addr}"]


def _assess_resource_compliance(
    resource: ResourceChange,
    resource_findings: list[Finding],
    gap_analyses: list[ComplianceGapAnalysis],
    acceptance: RiskAcceptanceRecord | None = None,
) -> ChangeRiskEntry:
    """Assess compliance impact for a single resource change."""
    affected_controls: list[str] = []
    gate = GateRecommendation.PASS
    justifications: list[str] = []

    # Collect affected controls from findings
    for finding in resource_findings:
        for ctrl in finding.compliance_controls:
            affected_controls.append(ctrl)

    # Check gap analyses for failing controls
    for ga in gap_analyses:
        fw = ga.framework
        fw_key = fw.value if hasattr(fw, "value") else str(fw)
        for ctrl in ga.controls:
            status = ctrl.status
            s_val = (
                status.value if hasattr(status, "value")
                else str(status)
            )
            if s_val == "FAIL":
                full_id = f"{fw_key}:{ctrl.control_id}"
                if full_id in _BLOCK_CONTROLS:
                    gate = GateRecommendation.BLOCK
                    justifications.append(
                        f"BLOCK: {full_id} "
                        f"({ctrl.control_title}) — "
                        f"control gap on {resource.address}"
                    )
                elif (
                    full_id in _WARN_CONTROLS
                    and gate != GateRecommendation.BLOCK
                ):
                    gate = GateRecommendation.WARN
                    justifications.append(
                        f"WARN: {full_id} "
                        f"({ctrl.control_title}) — "
                        f"requires remediation"
                    )

    # Apply risk acceptance — downgrade gate
    if acceptance and acceptance.accepted:
        if gate == GateRecommendation.BLOCK:
            gate = GateRecommendation.WARN
            justifications.append(
                f"ACCEPTED: Risk accepted by "
                f"{acceptance.approver or 'user'}. "
                f"Reason: {acceptance.comment}. "
                f"Expires: {acceptance.expiry_date or 'never'}"
            )
        elif gate == GateRecommendation.WARN:
            justifications.append(
                f"ACCEPTED: {acceptance.comment} "
                f"(expires: {acceptance.expiry_date or 'never'})"
            )

    # Check in-code risk acceptance from @risk- annotations
    if resource.risk_acceptance and not acceptance:
        ra = resource.risk_acceptance
        if ra.reason:
            if gate == GateRecommendation.BLOCK:
                gate = GateRecommendation.WARN
            justifications.append(
                f"IN-CODE ACCEPTED: {ra.reason} "
                f"(approver: {ra.approver or 'unknown'}, "
                f"expires: {ra.expires or 'never'})"
            )

    # Determine risk of change
    worst_severity = "low"
    for f in resource_findings:
        sev = (
            f.severity.value if hasattr(f.severity, "value")
            else str(f.severity)
        )
        risk = _SEVERITY_RISK.get(sev, "low")
        if risk == "high":
            worst_severity = "high"
        elif risk == "medium" and worst_severity != "high":
            worst_severity = "medium"

    action = (
        resource.action.value
        if hasattr(resource.action, "value")
        else str(resource.action)
    )

    return ChangeRiskEntry(
        resource_address=resource.address,
        resource_type=resource.resource_type,
        change_type=action,
        affected_controls=affected_controls,
        gate_recommendation=gate.value,
        justification=(
            "; ".join(justifications)
            if justifications
            else "No compliance gaps"
        ),
        rollback_steps=_generate_rollback_steps(resource),
        risk_of_change=worst_severity,
    )


class ChangeManagementAgent(BaseAgent):
    name = "change_management"
    critical = True

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, ChangeManagementInput):
            return ValidationResult(
                valid=False,
                error="Expected ChangeManagementInput",
            )
        return ValidationResult(valid=True)

    def assess(
        self, input_data: ChangeManagementInput,
    ) -> ChangeManagementOutput:
        inventory = input_data.inventory
        findings = input_data.findings
        gap_analyses = input_data.gap_analyses
        risk_acceptances = input_data.risk_acceptances
        entries: list[ChangeRiskEntry] = []

        # Build acceptance map by resource address
        acceptance_map: dict[str, RiskAcceptanceRecord] = {}
        for ra in risk_acceptances:
            if ra.accepted:
                acceptance_map[ra.resource_address] = ra

        # Group findings by resource
        findings_by_resource: dict[str, list[Finding]] = {}
        for f in findings:
            findings_by_resource.setdefault(
                f.resource_address, [],
            ).append(f)

        # Assess each resource
        for resource in inventory.resources:
            rf = findings_by_resource.get(resource.address, [])
            acceptance = acceptance_map.get(resource.address)
            entry = _assess_resource_compliance(
                resource, rf, gap_analyses, acceptance,
            )
            entries.append(entry)

        # Determine overall gate
        overall_gate = GateRecommendation.PASS
        block_reasons: list[str] = []
        warn_reasons: list[str] = []

        for entry in entries:
            if entry.gate_recommendation == "block":
                overall_gate = GateRecommendation.BLOCK
                block_reasons.append(
                    f"{entry.resource_address}: {entry.justification}"
                )
            elif entry.gate_recommendation == "warn":
                if overall_gate != GateRecommendation.BLOCK:
                    overall_gate = GateRecommendation.WARN
                warn_reasons.append(
                    f"{entry.resource_address}: {entry.justification}"
                )

        if overall_gate == GateRecommendation.BLOCK:
            justification = (
                f"BLOCKED: {len(block_reasons)} resource(s) have "
                f"compliance gaps requiring resolution. "
                + "; ".join(block_reasons[:3])
            )
        elif overall_gate == GateRecommendation.WARN:
            justification = (
                f"WARNING: {len(warn_reasons)} resource(s) have "
                f"compliance gaps requiring remediation. "
                + "; ".join(warn_reasons[:3])
            )
        else:
            justification = (
                "PASSED: No compliance gaps detected in changed resources."
            )

        # Audit summary
        audit_summary = (
            f"Assessed {len(inventory.resources)} resources, "
            f"{len(findings)} findings across "
            f"{len(gap_analyses)} frameworks. "
            f"Gate: {overall_gate.value}."
        )

        logger.info(
            "Change management assessment: gate=%s, resources=%d",
            overall_gate.value,
            len(entries),
        )

        return ChangeManagementOutput(
            change_entries=entries,
            gate_recommendation=overall_gate.value,
            gate_justification=justification,
            audit_summary=audit_summary,
        )
