"""Impact Assessment Agent — applies business context to findings using CIA triad."""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.enums import RiskLevel, Severity
from iac_risk.core.schemas import (
    BusinessContext,
    CIAImpact,
    Finding,
    ImpactAssessmentInput,
    ImpactAssessmentOutput,
    ImpactRating,
)
from iac_risk.services.nist_risk_model import calculate_risk_level, map_risk_to_severity

logger = logging.getLogger(__name__)

# Default CIA mapping when finding has no check-level CIA
_SEVERITY_TO_DEFAULT_CIA: dict[Severity, RiskLevel] = {
    Severity.CRITICAL: RiskLevel.HIGH,
    Severity.HIGH: RiskLevel.MODERATE,
    Severity.MODERATE: RiskLevel.LOW,
    Severity.LOW: RiskLevel.VERY_LOW,
    Severity.INFORMATIONAL: RiskLevel.VERY_LOW,
}


def _match_context(
    resource_address: str,
    contexts: list[BusinessContext],
) -> BusinessContext | None:
    """Find the best matching business context for a resource address."""
    for ctx in contexts:
        pattern = ctx.resource_pattern
        if fnmatch.fnmatch(resource_address, pattern):
            return ctx
        if fnmatch.fnmatch(resource_address, f"*{pattern}"):
            return ctx
        parts = resource_address.split(".")
        for i in range(len(parts) - 1):
            segment = f"{parts[i]}.{parts[i + 1]}"
            if fnmatch.fnmatch(segment, pattern):
                return ctx
    return None


def _elevate_level(base: RiskLevel, by: int) -> RiskLevel:
    """Elevate a RiskLevel by N steps, capped at VERY_HIGH."""
    levels = [
        RiskLevel.VERY_LOW,
        RiskLevel.LOW,
        RiskLevel.MODERATE,
        RiskLevel.HIGH,
        RiskLevel.VERY_HIGH,
    ]
    try:
        idx = levels.index(base)
    except ValueError:
        return base
    new_idx = min(idx + by, len(levels) - 1)
    return levels[new_idx]


def _apply_business_context(
    cia: CIAImpact, ctx: BusinessContext,
) -> tuple[RiskLevel, RiskLevel, RiskLevel]:
    """Elevate CIA impact based on business context.

    - Restricted/confidential data elevates Confidentiality
    - High/very-high asset criticality elevates all 3 dimensions
    - Multiple compliance frameworks elevate Integrity (audit requirements)
    """
    c = cia.confidentiality
    i = cia.integrity
    a = cia.availability

    # Data classification elevates confidentiality
    if ctx.data_classification == "restricted":
        c = _elevate_level(c, 2)
    elif ctx.data_classification == "confidential":
        c = _elevate_level(c, 1)

    # Asset criticality elevates all dimensions
    if ctx.asset_criticality == RiskLevel.VERY_HIGH:
        c = _elevate_level(c, 2)
        i = _elevate_level(i, 2)
        a = _elevate_level(a, 2)
    elif ctx.asset_criticality == RiskLevel.HIGH:
        c = _elevate_level(c, 1)
        i = _elevate_level(i, 1)
        a = _elevate_level(a, 1)

    # Multiple compliance frameworks elevate integrity
    if len(ctx.compliance_scope) >= 3:
        i = _elevate_level(i, 1)

    return c, i, a


class ImpactAssessmentAgent(BaseAgent):
    name = "impact_assessment"
    critical = True

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, ImpactAssessmentInput):
            return ValidationResult(valid=False, error="Expected ImpactAssessmentInput")
        return ValidationResult(valid=True)

    def assess(self, input_data: ImpactAssessmentInput) -> ImpactAssessmentOutput:
        findings = input_data.findings
        risk_dets = input_data.risk_determinations
        contexts = input_data.business_contexts

        finding_map: dict[str, Finding] = {f.finding_id: f for f in findings}
        ratings: list[ImpactRating] = []

        for det in risk_dets:
            finding = finding_map.get(det.finding_id)
            if not finding:
                continue

            # Start from check-level CIA impact
            base_cia = finding.cia_impact

            # Fallback: derive from severity if check has no CIA
            if (
                base_cia.confidentiality == RiskLevel.LOW
                and base_cia.integrity == RiskLevel.LOW
                and base_cia.availability == RiskLevel.LOW
            ):
                default = _SEVERITY_TO_DEFAULT_CIA.get(
                    finding.severity, RiskLevel.MODERATE,
                )
                base_cia = CIAImpact(
                    confidentiality=default,
                    integrity=default,
                    availability=default,
                )

            ctx = _match_context(finding.resource_address, contexts)

            if ctx:
                c, i, a = _apply_business_context(base_cia, ctx)
                annotation = (
                    f"Asset criticality: {ctx.asset_criticality.name}, "
                    f"Data: {ctx.data_classification}, "
                    f"Scope: {[f.value for f in ctx.compliance_scope]}"
                )
                if ctx.notes:
                    annotation += f". {ctx.notes}"
            else:
                c = base_cia.confidentiality
                i = base_cia.integrity
                a = base_cia.availability
                annotation = None

            overall = max(c, i, a)
            final_risk = calculate_risk_level(det.likelihood, overall)
            final_severity = map_risk_to_severity(final_risk)

            ratings.append(
                ImpactRating(
                    finding_id=det.finding_id,
                    confidentiality_impact=c,
                    integrity_impact=i,
                    availability_impact=a,
                    overall_impact=overall,
                    business_context_annotation=annotation,
                    final_risk_level=final_risk,
                    final_risk_severity=final_severity,
                )
            )

        logger.info(
            "Impact assessment complete: %d ratings (%d with business context)",
            len(ratings),
            sum(1 for r in ratings if r.business_context_annotation is not None),
        )

        return ImpactAssessmentOutput(impact_ratings=ratings)
