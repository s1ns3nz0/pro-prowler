"""Fix routes — generate remediation PRs via GitHub integration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from iac_risk.agents.change_management import ChangeManagementAgent
from iac_risk.core.schemas import (
    ChangeManagementInput,
    ComplianceGapAnalysis,
    ComplianceMappingOutput,
    Finding,
    ResourceInventory,
)
from iac_risk.web.config import WebConfig
from iac_risk.web.github_integration import (
    execute_fix,
)
from iac_risk.web.storage.database import get_snapshot
from iac_risk.web.storage.snapshot_store import load_snapshot

logger = logging.getLogger(__name__)
router = APIRouter()


class FixRequest(BaseModel):
    service: str = Field(description="Service group to fix, e.g. 'S3'")


class FixAllRequest(BaseModel):
    pass


class FixResponse(BaseModel):
    status: str  # "success", "error", "no_fixes"
    pr_url: str = ""
    pr_number: int | None = None
    branch: str = ""
    fixes_applied: int = 0
    error: str = ""


def _extract_output_safe(result: Any, agent: str) -> Any:
    ar = result.agent_results.get(agent)
    if not ar or not ar.output:
        return None
    return ar.output


def _get_findings_as_dicts(output: Any) -> list[dict]:
    if output is None:
        return []
    if isinstance(output, dict):
        return output.get("findings", [])
    return [f.model_dump() for f in output.findings]


def _get_findings_for_service(
    all_findings: list[dict], service: str,
) -> list[dict]:
    """Filter findings by service category."""
    from iac_risk.agents.risk_analysis import categorize_service
    return [
        f for f in all_findings
        if categorize_service(f.get("resource_type", "")) == service
    ]


def _run_change_review(
    findings: list[dict], result: Any,
) -> dict | None:
    """Run Change Management Agent on proposed fixes."""
    try:
        compliance_out = _extract_output_safe(result, "compliance_mapping")
        parser_out = _extract_output_safe(result, "iac_parser")

        if not parser_out:
            return None

        # Build inventory
        if isinstance(parser_out, dict):
            inv = ResourceInventory.model_validate(
                parser_out.get("inventory", {}),
            )
        else:
            inv = parser_out.inventory

        # Build findings
        finding_objs = [Finding.model_validate(f) for f in findings]

        # Build gap analyses
        gap_analyses: list[ComplianceGapAnalysis] = []
        if compliance_out:
            if isinstance(compliance_out, dict):
                co = ComplianceMappingOutput.model_validate(
                    compliance_out,
                )
                gap_analyses = co.gap_analyses
            else:
                gap_analyses = compliance_out.gap_analyses

        agent = ChangeManagementAgent()
        cm_input = ChangeManagementInput(
            inventory=inv,
            findings=finding_objs,
            gap_analyses=gap_analyses,
        )
        cm_result = agent.run(cm_input)
        if cm_result.output:
            return cm_result.output.model_dump()
    except Exception:
        logger.warning("Change review failed", exc_info=True)
    return None


@router.post(
    "/snapshots/{snapshot_id}/fix",
    response_model=FixResponse,
)
async def fix_service(
    snapshot_id: str, req: FixRequest, request: Request,
) -> FixResponse:
    """Create a fix PR for a specific service group."""
    config: WebConfig = request.app.state.config
    meta = get_snapshot(config.db_path, snapshot_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    result = load_snapshot(config.snapshots_dir, snapshot_id)
    misconfig_out = _extract_output_safe(result, "cloud_misconfig")
    all_findings = _get_findings_as_dicts(misconfig_out)
    service_findings = _get_findings_for_service(
        all_findings, req.service,
    )

    if not service_findings:
        return FixResponse(
            status="no_fixes",
            error=f"No findings for service {req.service}",
        )

    # Get repository from project
    from iac_risk.web.storage.database import get_project
    project = get_project(config.db_path, meta.project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )

    # Run change management review
    change_review = await asyncio.to_thread(
        _run_change_review, service_findings, result,
    )

    # Execute fix
    try:
        fix_result = await asyncio.to_thread(
            execute_fix,
            project.repository,
            req.service,
            snapshot_id,
            service_findings,
            change_review,
        )
    except RuntimeError as e:
        return FixResponse(status="error", error=str(e))
    except Exception as e:
        logger.exception("Fix execution failed")
        return FixResponse(status="error", error=str(e))

    if fix_result.get("error"):
        return FixResponse(
            status="no_fixes" if fix_result["fixes_applied"] == 0 else "error",
            error=fix_result["error"],
            fixes_applied=fix_result["fixes_applied"],
        )

    return FixResponse(
        status="success",
        pr_url=fix_result.get("pr_url", ""),
        pr_number=fix_result.get("pr_number"),
        branch=fix_result.get("branch", ""),
        fixes_applied=fix_result.get("fixes_applied", 0),
    )


@router.post(
    "/snapshots/{snapshot_id}/fix-all",
    response_model=list[FixResponse],
)
async def fix_all(
    snapshot_id: str, request: Request,
) -> list[FixResponse]:
    """Create fix PRs for all service groups with findings."""
    config: WebConfig = request.app.state.config
    meta = get_snapshot(config.db_path, snapshot_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    result = load_snapshot(config.snapshots_dir, snapshot_id)
    misconfig_out = _extract_output_safe(result, "cloud_misconfig")
    all_findings = _get_findings_as_dicts(misconfig_out)

    # Group by service
    from iac_risk.agents.risk_analysis import categorize_service
    services: dict[str, list[dict]] = {}
    for f in all_findings:
        svc = categorize_service(f.get("resource_type", ""))
        services.setdefault(svc, []).append(f)

    from iac_risk.web.storage.database import get_project
    project = get_project(config.db_path, meta.project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )

    results: list[FixResponse] = []
    for service, svc_findings in services.items():
        change_review = await asyncio.to_thread(
            _run_change_review, svc_findings, result,
        )
        try:
            fix_result = await asyncio.to_thread(
                execute_fix,
                project.repository,
                service,
                snapshot_id,
                svc_findings,
                change_review,
            )
            if fix_result.get("error"):
                results.append(FixResponse(
                    status="no_fixes",
                    error=f"{service}: {fix_result['error']}",
                ))
            else:
                results.append(FixResponse(
                    status="success",
                    pr_url=fix_result.get("pr_url", ""),
                    pr_number=fix_result.get("pr_number"),
                    branch=fix_result.get("branch", ""),
                    fixes_applied=fix_result.get("fixes_applied", 0),
                ))
        except Exception as e:
            results.append(FixResponse(
                status="error", error=f"{service}: {e}",
            ))

    return results
