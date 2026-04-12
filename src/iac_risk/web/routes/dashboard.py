"""Dashboard HTML routes — server-side rendered with Jinja2."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from iac_risk.agents.risk_analysis import categorize_service
from iac_risk.core.schemas import (
    PipelineResult,
)
from iac_risk.web.comparison import compare_snapshots
from iac_risk.web.config import WebConfig
from iac_risk.web.storage.database import (
    get_previous_for_plan,
    get_snapshot,
    list_projects,
    list_snapshots,
)
from iac_risk.web.storage.snapshot_store import load_snapshot

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
)


def _cfg(request: Request) -> WebConfig:
    return request.app.state.config


def _extract_output(result: PipelineResult, agent: str) -> Any:
    """Extract agent output, handling dict vs Pydantic model."""
    ar = result.agent_results.get(agent)
    if not ar or not ar.output:
        return None
    return ar.output


def _extract_findings(output: Any) -> list[dict]:
    """Extract findings as dicts from cloud_misconfig output."""
    if output is None:
        return []
    if isinstance(output, dict):
        raw = output.get("findings", [])
    else:
        raw = [f.model_dump() for f in output.findings]
    return raw


def _extract_attack_paths(output: Any) -> list[dict]:
    """Extract attack paths from risk_analysis output."""
    if output is None:
        return []
    if isinstance(output, dict):
        return output.get("attack_paths", [])
    return [ap.model_dump() for ap in output.attack_paths]


def _extract_impact_ratings(output: Any) -> dict[str, dict]:
    """Extract impact ratings keyed by finding_id."""
    if output is None:
        return {}
    if isinstance(output, dict):
        ratings = output.get("impact_ratings", [])
    else:
        ratings = [ir.model_dump() for ir in output.impact_ratings]
    return {r["finding_id"]: r for r in ratings}


def _extract_gap_analyses(output: Any) -> list[dict]:
    """Extract compliance gap analyses."""
    if output is None:
        return []
    if isinstance(output, dict):
        return output.get("gap_analyses", [])
    return [ga.model_dump() for ga in output.gap_analyses]


def _get_business_contexts(result: PipelineResult) -> list[dict]:
    """Extract business contexts from context analysis output."""
    ctx_out = _extract_output(result, "context_analysis")
    if ctx_out is None:
        return []
    if isinstance(ctx_out, dict):
        return ctx_out.get("contexts", [])
    return [c.model_dump() for c in ctx_out.contexts]


def _match_business_context(
    address: str, contexts: list[dict],
) -> dict | None:
    """Find matching business context for a resource address.

    Handles module-prefixed addresses like 'module.db.aws_db_instance.this'.
    """
    import fnmatch
    for ctx in contexts:
        pattern = ctx.get("resource_pattern", "")
        if fnmatch.fnmatch(address, pattern):
            return ctx
        if fnmatch.fnmatch(address, f"*{pattern}"):
            return ctx
        parts = address.split(".")
        for i in range(len(parts) - 1):
            segment = f"{parts[i]}.{parts[i + 1]}"
            if fnmatch.fnmatch(segment, pattern):
                return ctx
    return None


def _get_checks_for_resource(resource_type: str) -> list[dict]:
    """Get all Prowler checks applicable to a resource type."""
    from iac_risk.services.prowler_catalog import ProwlerCatalog
    catalog = ProwlerCatalog()
    checks = catalog.get_checks_for_resource_type(resource_type)
    return [
        {
            "check_id": c.check_id,
            "title": c.title,
            "severity": c.severity.value,
            "description": c.description,
        }
        for c in checks
    ]


_RESOURCE_DESCRIPTIONS: dict[str, str] = {
    "aws_s3_bucket": "Object storage for files, backups, logs, and static assets",
    "aws_s3_bucket_versioning": "Version control for S3 bucket objects",
    "aws_s3_bucket_server_side_encryption_configuration": (
        "Encryption settings for S3 bucket data at rest"
    ),
    "aws_s3_bucket_public_access_block": (
        "Controls preventing public access to S3 bucket contents"
    ),
    "aws_s3_bucket_lifecycle_configuration": (
        "Lifecycle rules for automatic object transition and expiration"
    ),
    "aws_s3_bucket_logging": "Access logging configuration for S3 bucket audit trail",
    "aws_db_instance": "Managed relational database (RDS) for structured data storage",
    "aws_db_subnet_group": "Database subnet placement controlling network isolation",
    "aws_instance": "Virtual server (EC2) running application workloads",
    "aws_lb": "Application or Network Load Balancer distributing traffic to backends",
    "aws_lb_listener": "Load balancer listener defining how incoming traffic is routed",
    "aws_lb_target_group": "Routes traffic from the load balancer to backend compute targets",
    "aws_security_group": "Firewall rules controlling inbound and outbound network traffic",
    "aws_vpc": "Virtual Private Cloud providing network isolation for all resources",
    "aws_subnet": "Network subdivision within a VPC for resource placement",
    "aws_route_table": "Network routing rules controlling traffic flow between subnets",
    "aws_route_table_association": "Links a subnet to a route table for traffic routing",
    "aws_internet_gateway": "Enables internet connectivity for public-facing resources",
    "aws_nat_gateway": "Enables outbound internet access for private subnet resources",
    "aws_eip": "Static public IP address for consistent external addressing",
    "aws_ecs_cluster": "Container orchestration cluster managing ECS services",
    "aws_ecs_service": "Long-running containerized application with scaling and health checks",
    "aws_ecs_task_definition": (
        "Container config defining image, CPU, memory, and networking"
    ),
    "aws_ecr_repository": "Private Docker image registry for container deployments",
    "aws_iam_role": "Identity role defining permissions for AWS services and users",
    "aws_iam_role_policy_attachment": "Attaches a permissions policy to an IAM role",
    "aws_iam_policy": "Set of permissions defining what actions are allowed on which resources",
    "aws_lambda_function": "Serverless function executing code without managing servers",
    "aws_cloudwatch_log_group": "Centralized log storage for monitoring and audit",
    "aws_kms_key": "Encryption key for protecting data at rest and in transit",
    "aws_secretsmanager_secret": "Secure storage for credentials, API keys, and sensitive config",
    "aws_dynamodb_table": "NoSQL database for high-performance key-value workloads",
    "aws_sqs_queue": "Message queue for decoupling and async communication between services",
    "aws_sns_topic": "Pub/sub messaging for notifications and event distribution",
    "aws_cloudfront_distribution": "CDN for global content delivery and edge caching",
    "aws_cloudtrail": "API activity logging for security audit and compliance",
    "aws_api_gateway_stage": "API Gateway deployment stage (dev/staging/prod)",
}


def _calc_resource_score(findings: list[dict]) -> int:
    """Calculate a 0-100 composite score for a resource."""
    weights = {
        "CRITICAL": 15,
        "HIGH": 8,
        "MODERATE": 3,
        "LOW": 1,
        "INFORMATIONAL": 0,
    }
    deduction = sum(
        weights.get(f.get("severity", "MODERATE"), 3)
        for f in findings
    )
    return max(0, 100 - deduction)


def _build_service_groups(
    result: PipelineResult,
) -> dict[str, list[dict]]:
    """Group resources by service with their findings and attack paths."""
    misconfig_out = _extract_output(result, "cloud_misconfig")
    risk_out = _extract_output(result, "risk_analysis")
    impact_out = _extract_output(result, "impact_assessment")
    parser_out = _extract_output(result, "iac_parser")
    business_contexts = _get_business_contexts(result)

    findings = _extract_findings(misconfig_out)
    attack_paths = _extract_attack_paths(risk_out)
    impact_map = _extract_impact_ratings(impact_out)

    # Get all resources from parser
    all_resources: list[dict] = []
    if parser_out:
        if isinstance(parser_out, dict):
            inv = parser_out.get("inventory", {})
            all_resources = inv.get("resources", [])
        else:
            all_resources = [
                r.model_dump() for r in parser_out.inventory.resources
            ]

    # Index findings and attack paths by resource address
    findings_by_resource: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        # Enrich with risk score from impact
        ir = impact_map.get(f.get("finding_id", ""))
        if ir:
            f["risk_score"] = ir.get("final_risk_level", 0)
        else:
            f["risk_score"] = 0

        # Ensure attack_scenarios are dicts
        scenarios = f.get("attack_scenarios", [])
        if scenarios and not isinstance(scenarios[0], dict):
            f["attack_scenarios"] = [s.model_dump() for s in scenarios]

        findings_by_resource[f["resource_address"]].append(f)

    paths_by_resource: dict[str, dict] = {}
    for ap in attack_paths:
        addr = ap.get("resource_address", "")
        if addr:
            paths_by_resource[addr] = ap

    # Build service groups
    groups: dict[str, list[dict]] = defaultdict(list)
    seen_addresses: set[str] = set()

    for res in all_resources:
        addr = res.get("address", "")
        rtype = res.get("resource_type", "")
        service = categorize_service(rtype)
        seen_addresses.add(addr)

        resource_findings = findings_by_resource.get(addr, [])
        max_risk = max(
            (f.get("risk_score", 0) for f in resource_findings), default=0,
        )

        # Business context
        ctx = _match_business_context(addr, business_contexts)
        criticality = "MODERATE"
        data_class = "internal"
        compliance_scope: list[str] = []
        context_notes = ""
        context_source = "default"
        if ctx:
            crit = ctx.get("asset_criticality")
            if isinstance(crit, int):
                crit_names = {
                    1: "VERY_LOW", 2: "LOW", 3: "MODERATE",
                    4: "HIGH", 5: "VERY_HIGH",
                }
                criticality = crit_names.get(crit, "MODERATE")
            elif isinstance(crit, str):
                criticality = crit
            data_class = ctx.get("data_classification", "internal")
            scope = ctx.get("compliance_scope", [])
            compliance_scope = [
                s.get("value", s) if isinstance(s, dict) else str(s)
                for s in scope
            ]
            context_notes = ctx.get("notes", "")
            context_source = "business_context"

        # Checks evaluated for this resource type
        failed_check_ids = {f.get("check_id") for f in resource_findings}
        all_checks = _get_checks_for_resource(rtype)
        passed_checks = [c for c in all_checks if c["check_id"] not in failed_check_ids]

        groups[service].append({
            "address": addr,
            "resource_type": rtype,
            "findings": resource_findings,
            "attack_path": paths_by_resource.get(addr),
            "after_config": res.get("after_config") or {},
            "max_risk_score": max_risk,
            "resource_score": _calc_resource_score(resource_findings),
            "finding_count": len(resource_findings),
            "asset_criticality": criticality,
            "data_classification": data_class,
            "compliance_scope": compliance_scope,
            "context_notes": context_notes,
            "context_source": context_source,
            "passed_checks": passed_checks,
            "total_checks_evaluated": len(all_checks),
            "resource_description": _RESOURCE_DESCRIPTIONS.get(rtype, ""),
            "config_summary": res.get("config_summary", ""),
        })

    # Add any findings for resources not in parser output
    for addr, fs in findings_by_resource.items():
        if addr not in seen_addresses:
            rtype = fs[0].get("resource_type", "") if fs else ""
            service = categorize_service(rtype)
            max_risk = max(
                (f.get("risk_score", 0) for f in fs), default=0,
            )
            groups[service].append({
                "address": addr,
                "resource_type": rtype,
                "findings": fs,
                "attack_path": paths_by_resource.get(addr),
                "after_config": {},
                "max_risk_score": max_risk,
                "resource_score": _calc_resource_score(fs),
                "finding_count": len(fs),
                "asset_criticality": "MODERATE",
                "data_classification": "internal",
                "compliance_scope": [],
                "context_notes": "",
                "context_source": "default",
                "passed_checks": [],
                "total_checks_evaluated": 0,
                "resource_description": _RESOURCE_DESCRIPTIONS.get(rtype, ""),
                "config_summary": "",
            })

    # Sort groups by lowest resource score (worst first)
    sorted_groups = dict(
        sorted(
            groups.items(),
            key=lambda x: min(
                (r["resource_score"] for r in x[1]), default=100,
            ),
        )
    )
    return sorted_groups


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_home(request: Request) -> HTMLResponse:
    """Project list page with trend chart."""
    config = _cfg(request)
    projects_raw = list_projects(config.db_path)

    projects = []
    for p in projects_raw:
        trend = ""
        if p.latest_score is not None and p.previous_score is not None:
            if p.latest_score > p.previous_score:
                trend = "up"
            elif p.latest_score < p.previous_score:
                trend = "down"
            else:
                trend = "flat"
        projects.append({
            "id": p.id,
            "repository": p.repository,
            "created_at": p.created_at,
            "updated_at": p.updated_at,
            "latest_score": p.latest_score,
            "latest_grade": p.latest_grade,
            "snapshot_count": p.snapshot_count,
            "default_branch": p.default_branch,
            "trend": trend,
        })

    # Get recent snapshots for trend chart
    all_snapshots, _ = list_snapshots(config.db_path, limit=20)

    template = _env.get_template("home.html.j2")
    html = template.render(
        projects=projects,
        all_snapshots=all_snapshots,
    )
    return HTMLResponse(content=html)


@router.get(
    "/dashboard/snapshots/{snapshot_id}", response_class=HTMLResponse,
)
async def dashboard_detail(
    snapshot_id: str, request: Request,
) -> HTMLResponse:
    """Snapshot detail page with service-grouped resources."""
    config = _cfg(request)
    meta = get_snapshot(config.db_path, snapshot_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    result = load_snapshot(config.snapshots_dir, snapshot_id)

    # Get repository name from project
    from iac_risk.web.storage.database import get_project
    project = get_project(config.db_path, meta.project_id)
    repository = project.repository if project else "unknown"

    # Build service groups
    service_groups = _build_service_groups(result)

    # Auto-compare
    comparison = None
    prev = get_previous_for_plan(
        config.db_path, meta.plan_hash, snapshot_id,
    )
    if prev:
        try:
            prev_result = load_snapshot(config.snapshots_dir, prev.id)
            comparison = compare_snapshots(
                prev_result, result, prev.id, snapshot_id,
            )
        except Exception:
            pass

    # Compliance summary
    compliance_out = _extract_output(result, "compliance_mapping")
    gap_analyses_raw = _extract_gap_analyses(compliance_out)
    gap_analyses = []
    for ga in gap_analyses_raw:
        fw = ga.get("framework", "")
        if isinstance(fw, dict):
            fw = fw.get("value", str(fw))
        elif hasattr(fw, "value"):
            fw = fw.value
        gap_analyses.append({
            "framework": fw,
            "coverage": ga.get("coverage_score", 0),
            "passing": ga.get("passing_count", 0),
            "failing": ga.get("failing_count", 0),
            "unmapped": ga.get("unmapped_count", 0),
        })

    # Serialize resource data as JSON for the JS split view
    resource_data_json = json.dumps(
        {
            svc: [
                {
                    "address": r["address"],
                    "resource_type": r["resource_type"],
                    "findings": r["findings"],
                    "attack_path": r.get("attack_path"),
                    "after_config": r.get("after_config", {}),
                    "asset_criticality": r.get("asset_criticality", "MODERATE"),
                    "data_classification": r.get("data_classification", "internal"),
                    "compliance_scope": r.get("compliance_scope", []),
                    "context_notes": r.get("context_notes", ""),
                    "context_source": r.get("context_source", "default"),
                    "passed_checks": r.get("passed_checks", []),
                    "total_checks_evaluated": r.get("total_checks_evaluated", 0),
                    "resource_score": r.get("resource_score", 100),
                    "resource_description": r.get("resource_description", ""),
                    "config_summary": r.get("config_summary", ""),
                }
                for r in resources
            ]
            for svc, resources in service_groups.items()
        },
        default=str,
    )

    # Build compliance-grouped view data
    compliance_groups: dict[str, list[dict]] = {}
    misconfig_out = _extract_output(result, "cloud_misconfig")
    all_findings = _extract_findings(misconfig_out)
    for ga in gap_analyses:
        fw = ga["framework"]
        controls_data = []
        # Get the raw gap analysis for this framework
        raw_ga = next(
            (g for g in gap_analyses_raw
             if (g.get("framework", {}).get("value", g.get("framework", ""))
                 if isinstance(g.get("framework"), dict)
                 else (g.get("framework").value
                       if hasattr(g.get("framework"), "value")
                       else g.get("framework", ""))) == fw),
            None,
        )
        if raw_ga:
            raw_controls = raw_ga.get("controls", [])
            if not isinstance(raw_controls, list):
                try:
                    raw_controls = [
                        c.model_dump() for c in raw_controls
                    ]
                except Exception:
                    raw_controls = []
            for ctrl in raw_controls:
                status = ctrl.get("status", "")
                if isinstance(status, dict):
                    status = status.get("value", "")
                elif hasattr(status, "value"):
                    status = status.value
                related = ctrl.get("related_finding_ids", [])
                # Find related findings
                ctrl_findings = [
                    f for f in all_findings
                    if f.get("finding_id", "") in related
                ]
                controls_data.append({
                    "control_id": ctrl.get("control_id", ""),
                    "control_title": ctrl.get("control_title", ""),
                    "status": status,
                    "finding_count": len(related),
                    "findings": ctrl_findings,
                })
        compliance_groups[fw] = controls_data

    compliance_groups_json = json.dumps(
        compliance_groups, default=str,
    )

    # Gate info from change management
    cm_out = _extract_output(result, "change_management")
    gate = meta.gate
    gate_justification = ""
    if cm_out:
        if isinstance(cm_out, dict):
            gate = cm_out.get("gate_recommendation", gate)
            gate_justification = cm_out.get(
                "gate_justification", "",
            )
        else:
            gate = cm_out.gate_recommendation
            gate_justification = cm_out.gate_justification

    template = _env.get_template("detail.html.j2")
    html = template.render(
        snapshot_id=snapshot_id,
        meta=meta,
        project_id=meta.project_id,
        repository=repository,
        commit_hash=meta.commit_hash,
        service_groups=service_groups,
        comparison=comparison,
        gap_analyses=gap_analyses,
        resource_data_json=resource_data_json,
        compliance_groups_json=compliance_groups_json,
        gate=gate,
        gate_justification=gate_justification,
        default_branch=project.default_branch if project else "main",
    )
    return HTMLResponse(content=html)


@router.get(
    "/dashboard/snapshots/{snapshot_id}/compare/{other_id}",
    response_class=HTMLResponse,
)
async def dashboard_compare(
    snapshot_id: str, other_id: str, request: Request,
) -> HTMLResponse:
    """Side-by-side comparison page."""
    config = _cfg(request)
    for sid in (snapshot_id, other_id):
        if not get_snapshot(config.db_path, sid):
            raise HTTPException(
                status_code=404, detail=f"Snapshot {sid} not found",
            )

    old_result = load_snapshot(config.snapshots_dir, other_id)
    new_result = load_snapshot(config.snapshots_dir, snapshot_id)
    comparison = compare_snapshots(
        old_result, new_result, other_id, snapshot_id,
    )

    template = _env.get_template("comparison.html.j2")
    html = template.render(
        old_id=other_id,
        new_id=snapshot_id,
        old_result=old_result,
        new_result=new_result,
        comparison=comparison,
    )
    return HTMLResponse(content=html)
