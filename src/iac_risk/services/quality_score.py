"""Aggregate quality scoring and letter grade calculation."""

from iac_risk.core.enums import LetterGrade, Severity
from iac_risk.core.schemas import Finding, ImpactRating, QualityScore

# Weights per severity level (points deducted from 100)
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 8,
    Severity.MODERATE: 3,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


def _determine_grade(score: int) -> LetterGrade:
    if score >= 90:
        return LetterGrade.A
    if score >= 75:
        return LetterGrade.B
    if score >= 60:
        return LetterGrade.C
    if score >= 40:
        return LetterGrade.D
    return LetterGrade.F


def calculate_quality_score(
    findings: list[Finding],
    impact_ratings: list[ImpactRating],
    compliance_coverage: dict[str, float] | None = None,
) -> QualityScore:
    """Calculate aggregate quality score from findings and impact ratings.

    Uses the final_risk_severity from impact ratings when available,
    otherwise falls back to finding severity.
    """
    # Build a lookup from finding_id -> final severity
    impact_severity_map: dict[str, Severity] = {}
    for ir in impact_ratings:
        impact_severity_map[ir.finding_id] = ir.final_risk_severity

    # Count findings by their effective severity
    finding_counts: dict[str, int] = {s.value: 0 for s in Severity}
    total_deduction = 0

    for finding in findings:
        effective_severity = impact_severity_map.get(finding.finding_id, finding.severity)
        finding_counts[effective_severity.value] += 1
        total_deduction += SEVERITY_WEIGHTS.get(effective_severity, 0)

    score = max(0, 100 - total_deduction)
    grade = _determine_grade(score)

    return QualityScore(
        score=score,
        grade=grade,
        finding_counts=finding_counts,
        compliance_coverage=compliance_coverage or {},
    )
