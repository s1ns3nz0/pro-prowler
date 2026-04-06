"""Snapshot comparison algorithm."""

from __future__ import annotations

from iac_risk.core.schemas import Finding, PipelineResult
from iac_risk.web.schemas import (
    ComparisonResult,
    ComplianceDelta,
    FindingSummary,
)


def _extract_findings(result: PipelineResult) -> list[Finding]:
    """Extract findings from a PipelineResult, handling missing data."""
    misconfig = result.agent_results.get("cloud_misconfig")
    if not misconfig or not misconfig.output:
        return []
    output = misconfig.output
    # After JSON round-trip, output may be a dict instead of typed model
    if isinstance(output, dict):
        findings_data = output.get("findings", [])
        return [Finding.model_validate(f) for f in findings_data]
    return output.findings


def _finding_key(f: Finding) -> tuple[str, str]:
    """Stable identity for a finding across runs."""
    return (f.check_id, f.resource_address)


def _to_summary(f: Finding) -> FindingSummary:
    return FindingSummary(
        check_id=f.check_id,
        resource_address=f.resource_address,
        severity=f.severity.value,
        title=f.title,
    )


def _extract_compliance_coverage(
    result: PipelineResult,
) -> dict[str, float]:
    """Extract per-framework coverage from a PipelineResult."""
    compliance = result.agent_results.get("compliance_mapping")
    if not compliance or not compliance.output:
        return {}
    output = compliance.output
    if isinstance(output, dict):
        from iac_risk.core.schemas import ComplianceMappingOutput
        output = ComplianceMappingOutput.model_validate(output)
    return {
        ga.framework.value: ga.coverage_score
        for ga in output.gap_analyses
    }


def compare_snapshots(
    old: PipelineResult, new: PipelineResult,
    old_id: str = "", new_id: str = "",
) -> ComparisonResult:
    """Compare two assessment snapshots and produce a diff."""
    old_findings = _extract_findings(old)
    new_findings = _extract_findings(new)

    old_map = {_finding_key(f): f for f in old_findings}
    new_map = {_finding_key(f): f for f in new_findings}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    new_only = sorted(new_keys - old_keys)
    resolved_only = sorted(old_keys - new_keys)
    persistent = sorted(old_keys & new_keys)

    # Compliance deltas
    old_coverage = _extract_compliance_coverage(old)
    new_coverage = _extract_compliance_coverage(new)
    all_frameworks = sorted(
        set(old_coverage.keys()) | set(new_coverage.keys())
    )
    compliance_deltas = [
        ComplianceDelta(
            framework=fw,
            old_coverage=old_coverage.get(fw, 0.0),
            new_coverage=new_coverage.get(fw, 0.0),
            delta=round(
                new_coverage.get(fw, 0.0) - old_coverage.get(fw, 0.0), 1,
            ),
        )
        for fw in all_frameworks
    ]

    return ComparisonResult(
        old_snapshot_id=old_id,
        new_snapshot_id=new_id,
        old_score=old.quality_score.score,
        new_score=new.quality_score.score,
        score_delta=new.quality_score.score - old.quality_score.score,
        old_grade=old.quality_score.grade.value,
        new_grade=new.quality_score.grade.value,
        grade_changed=(
            old.quality_score.grade != new.quality_score.grade
        ),
        new_findings=[_to_summary(new_map[k]) for k in new_only],
        resolved_findings=[_to_summary(old_map[k]) for k in resolved_only],
        persistent_findings=[_to_summary(new_map[k]) for k in persistent],
        compliance_deltas=compliance_deltas,
    )
