"""Impact Assessment Agent — applies business context to risk determinations."""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.enums import RiskLevel, Severity
from iac_risk.core.schemas import (
    BusinessContext,
    Finding,
    ImpactAssessmentInput,
    ImpactAssessmentOutput,
    ImpactRating,
)
from iac_risk.services.nist_risk_model import calculate_risk_level, map_risk_to_severity

logger = logging.getLogger(__name__)

# Default impact mapping when no business context is available
_SEVERITY_TO_DEFAULT_IMPACT: dict[Severity, RiskLevel] = {
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
    """Find the best matching business context for a resource address.

    Handles module-prefixed addresses like 'module.db.aws_db_instance.this'
    by also matching against each dotted segment of the address.
    """
    for ctx in contexts:
        pattern = ctx.resource_pattern
        # Direct match
        if fnmatch.fnmatch(resource_address, pattern):
            return ctx
        # Match against address with wildcard prefix (module paths)
        if fnmatch.fnmatch(resource_address, f"*{pattern}"):
            return ctx
        # Match against each segment pair (type.name) in the address
        parts = resource_address.split(".")
        for i in range(len(parts) - 1):
            segment = f"{parts[i]}.{parts[i + 1]}"
            if fnmatch.fnmatch(segment, pattern):
                return ctx
    return None


def _determine_impact_from_context(ctx: BusinessContext) -> dict[str, RiskLevel]:
    """Derive four impact dimensions from business context."""
    criticality = ctx.asset_criticality

    # Mission impact = asset criticality
    mission = criticality

    # Asset impact based on data classification
    data_map = {
        "restricted": RiskLevel.VERY_HIGH,
        "confidential": RiskLevel.HIGH,
        "internal": RiskLevel.MODERATE,
        "public": RiskLevel.LOW,
    }
    asset = data_map.get(ctx.data_classification, RiskLevel.MODERATE)

    # Individual impact: higher if PII-related frameworks are in scope
    pii_frameworks = {"ISO_27701"}
    has_pii = any(f.value in pii_frameworks for f in ctx.compliance_scope)
    individual = RiskLevel.HIGH if has_pii else RiskLevel.LOW

    # Organizational impact based on number of compliance frameworks
    if len(ctx.compliance_scope) >= 3:
        organizational = RiskLevel.VERY_HIGH
    elif len(ctx.compliance_scope) >= 2:
        organizational = RiskLevel.HIGH
    elif len(ctx.compliance_scope) >= 1:
        organizational = RiskLevel.MODERATE
    else:
        organizational = RiskLevel.LOW

    return {
        "mission": mission,
        "asset": asset,
        "individual": individual,
        "organizational": organizational,
    }


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

        # Build lookup
        finding_map: dict[str, Finding] = {f.finding_id: f for f in findings}
        ratings: list[ImpactRating] = []

        for det in risk_dets:
            finding = finding_map.get(det.finding_id)
            if not finding:
                continue

            ctx = _match_context(finding.resource_address, contexts)

            if ctx:
                impacts = _determine_impact_from_context(ctx)
                annotation = (
                    f"Asset criticality: {ctx.asset_criticality.name}, "
                    f"Data: {ctx.data_classification}, "
                    f"Scope: {[f.value for f in ctx.compliance_scope]}"
                )
                if ctx.notes:
                    annotation += f". {ctx.notes}"
            else:
                # Default: derive impact from finding severity
                default_impact = _SEVERITY_TO_DEFAULT_IMPACT.get(
                    finding.severity, RiskLevel.MODERATE
                )
                impacts = {
                    "mission": default_impact,
                    "asset": default_impact,
                    "individual": RiskLevel.LOW,
                    "organizational": default_impact,
                }
                annotation = None

            overall = max(impacts.values())
            final_risk = calculate_risk_level(det.likelihood, overall)
            final_severity = map_risk_to_severity(final_risk)

            ratings.append(
                ImpactRating(
                    finding_id=det.finding_id,
                    mission_impact=impacts["mission"],
                    asset_impact=impacts["asset"],
                    individual_impact=impacts["individual"],
                    organizational_impact=impacts["organizational"],
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
