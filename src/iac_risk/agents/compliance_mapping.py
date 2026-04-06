"""Compliance Mapping Agent — static lookup + AI context annotations."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.enums import ComplianceFramework, ControlStatus
from iac_risk.core.schemas import (
    BusinessContext,
    ComplianceControl,
    ComplianceGapAnalysis,
    ComplianceMappingInput,
    ComplianceMappingOutput,
    ImpactRating,
)
from iac_risk.services.prowler_catalog import ProwlerCatalog

logger = logging.getLogger(__name__)

_DEFAULT_MAPPINGS_DIR = (
    Path(__file__).resolve().parent.parent / "data" / "compliance_mappings"
)

_FRAMEWORK_TO_FILE: dict[ComplianceFramework, str] = {
    ComplianceFramework.PCI_DSS: "pci_dss.yaml",
    ComplianceFramework.ISO_27001: "iso_27001.yaml",
    ComplianceFramework.ISO_27701: "iso_27701.yaml",
    ComplianceFramework.SOC_2: "soc2.yaml",
    ComplianceFramework.GDPR: "gdpr.yaml",
    ComplianceFramework.ISMS_P: "isms_p.yaml",
}


def _load_framework_controls(
    mappings_dir: Path, framework: ComplianceFramework
) -> list[dict[str, str]]:
    """Load control definitions for a framework from YAML."""
    filename = _FRAMEWORK_TO_FILE.get(framework)
    if not filename:
        return []
    path = mappings_dir / filename
    if not path.exists():
        return []
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("controls", [])


class ComplianceMappingAgent(BaseAgent):
    name = "compliance_mapping"
    critical = True

    def __init__(
        self,
        catalog: ProwlerCatalog | None = None,
        mappings_dir: Path | None = None,
    ) -> None:
        self.catalog = catalog or ProwlerCatalog()
        self.mappings_dir = mappings_dir or _DEFAULT_MAPPINGS_DIR

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, ComplianceMappingInput):
            return ValidationResult(valid=False, error="Expected ComplianceMappingInput")
        return ValidationResult(valid=True)

    def assess(self, input_data: ComplianceMappingInput) -> ComplianceMappingOutput:
        findings = input_data.findings
        impact_ratings = input_data.impact_ratings
        contexts = input_data.business_contexts
        frameworks = input_data.frameworks

        # Build lookups
        impact_map: dict[str, ImpactRating] = {ir.finding_id: ir for ir in impact_ratings}

        # Build finding -> check_id -> control_ids mapping
        finding_controls: dict[str, dict[str, list[str]]] = {}
        for f in findings:
            check = self.catalog.get_check_by_id(f.check_id)
            if check:
                finding_controls[f.finding_id] = check.compliance_mappings

        gap_analyses: list[ComplianceGapAnalysis] = []

        for framework in frameworks:
            fw_key = framework.value
            control_defs = _load_framework_controls(self.mappings_dir, framework)

            # Find which controls are affected by findings
            control_to_findings: dict[str, list[str]] = {}
            for finding_id, mappings in finding_controls.items():
                for ctrl_id in mappings.get(fw_key, []):
                    control_to_findings.setdefault(ctrl_id, []).append(finding_id)

            controls: list[ComplianceControl] = []
            passing = 0
            failing = 0
            unmapped = 0

            for ctrl_def in control_defs:
                ctrl_id = ctrl_def["control_id"]
                related = control_to_findings.get(ctrl_id, [])

                if related:
                    status = ControlStatus.FAIL
                    failing += 1
                else:
                    # Check if any Prowler check covers this control
                    covered = self._is_control_covered(fw_key, ctrl_id)
                    if covered:
                        status = ControlStatus.PASS
                        passing += 1
                    else:
                        status = ControlStatus.UNMAPPED
                        unmapped += 1

                # Build context annotation from impact ratings
                annotation = self._build_annotation(related, impact_map, contexts)

                controls.append(
                    ComplianceControl(
                        framework=framework,
                        control_id=ctrl_id,
                        control_title=ctrl_def.get("control_title", ""),
                        status=status,
                        related_finding_ids=related,
                        context_annotation=annotation,
                    )
                )

            total = len(controls)
            coverage = (passing / total * 100) if total > 0 else 0.0

            gap_analyses.append(
                ComplianceGapAnalysis(
                    framework=framework,
                    controls=controls,
                    coverage_score=round(coverage, 1),
                    passing_count=passing,
                    failing_count=failing,
                    unmapped_count=unmapped,
                    total_count=total,
                )
            )

        logger.info(
            "Compliance mapping complete: %d frameworks analyzed",
            len(gap_analyses),
        )

        return ComplianceMappingOutput(gap_analyses=gap_analyses)

    def _is_control_covered(self, framework_key: str, control_id: str) -> bool:
        """Check if any Prowler check in the catalog maps to this control."""
        for check in self.catalog.get_all_checks():
            if control_id in check.compliance_mappings.get(framework_key, []):
                return True
        return False

    def _build_annotation(
        self,
        finding_ids: list[str],
        impact_map: dict[str, ImpactRating],
        contexts: list[BusinessContext],
    ) -> str | None:
        """Build context annotation from impact ratings and business context."""
        annotations: list[str] = []
        for fid in finding_ids:
            ir = impact_map.get(fid)
            if ir and ir.business_context_annotation:
                annotations.append(ir.business_context_annotation)
        return "; ".join(annotations) if annotations else None
