"""POST /api/assess — run pipeline, store snapshot, auto-compare."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, HTTPException, Request

from iac_risk.core.schemas import PipelineConfig
from iac_risk.orchestrator.runner import PipelineRunner
from iac_risk.services.content_hash import hash_string
from iac_risk.services.prowler_catalog import ProwlerCatalog
from iac_risk.web.comparison import compare_snapshots
from iac_risk.web.config import WebConfig
from iac_risk.web.schemas import (
    AssessRequest,
    AssessResponse,
    ComparisonSummary,
)
from iac_risk.web.storage.database import (
    SnapshotMeta,
    get_or_create_project,
    get_previous_for_plan,
    insert_snapshot,
    list_governance_docs,
)
from iac_risk.web.storage.snapshot_store import load_snapshot, save_snapshot

logger = logging.getLogger(__name__)
router = APIRouter()


def _extract_changed_resources(result: object) -> list[dict]:
    """Extract resource list from pipeline result for audit."""
    try:
        parser = result.agent_results.get("iac_parser")  # type: ignore[attr-defined]
        if parser and parser.output:
            out = parser.output
            resources = (
                out.get("inventory", {}).get("resources", [])
                if isinstance(out, dict)
                else out.inventory.resources
            )
            return [
                {
                    "address": getattr(r, "address", r.get("address", "")),
                    "type": getattr(r, "resource_type", r.get("resource_type", "")),
                    "action": getattr(
                        getattr(r, "action", r.get("action", "")),
                        "value",
                        str(r.get("action", "")),
                    ),
                }
                for r in resources
            ]
    except Exception:
        pass
    return []


def _build_extra_documents(config: WebConfig) -> list[str]:
    """Load governance doc summaries and build context strings."""
    import json as _json

    docs: list[str] = []
    gov_dir = config.data_dir / "governance"

    # Governance document summaries
    try:
        gov_docs = list_governance_docs(config.db_path)
        for gdoc in gov_docs:
            summary_file = gov_dir / f"{gdoc.id}.summary.json"
            text_file = gov_dir / f"{gdoc.id}.txt"
            parts = [f"Governance document: {gdoc.title}"]
            if summary_file.exists():
                try:
                    summary = _json.loads(summary_file.read_text())
                    if summary.get("summary"):
                        parts.append(f"Summary: {summary['summary']}")
                    for key in (
                        "data_classification_rules",
                        "compliance_scope_rules",
                        "security_policies",
                    ):
                        items = summary.get(key, [])
                        if items:
                            parts.append(f"{key.replace('_', ' ').title()}:")
                            for item in items[:5]:
                                parts.append(f"  - {item}")
                except Exception:
                    pass
            elif text_file.exists():
                parts.append(text_file.read_text()[:2000])
            if len(parts) > 1:
                docs.append("\n".join(parts))
    except Exception:
        logger.warning("Failed to load governance docs for context")

    return docs


def _run_pipeline(
    plan_data: dict, req: AssessRequest,
    linked_repos: list | None = None,
    extra_documents: list[str] | None = None,
) -> object:
    """Run the assessment pipeline (synchronous)."""
    from iac_risk.core.schemas import LinkedRepo
    lr = []
    if linked_repos:
        for r in linked_repos:
            if isinstance(r, dict):
                lr.append(LinkedRepo(
                    repository=r.get("repository", ""),
                    repo_type=r.get("repo_type", "application"),
                ))
            elif isinstance(r, str):
                lr.append(LinkedRepo(repository=r))

    pipeline_config = PipelineConfig(
        skip_context_analysis=req.skip_context_analysis,
        fail_threshold=req.fail_threshold,
        repository=req.repository,
        linked_repos=lr,
        extra_documents=extra_documents or [],
    )
    catalog = ProwlerCatalog()
    runner = PipelineRunner(
        config=pipeline_config, plan_data=plan_data, catalog=catalog,
    )
    return runner.run()


@router.post("/assess", response_model=AssessResponse)
async def assess(req: AssessRequest, request: Request) -> AssessResponse:
    """Run IaC risk assessment and store the snapshot."""
    config: WebConfig = request.app.state.config

    if not req.repository:
        raise HTTPException(
            status_code=400, detail="repository is required",
        )

    # Fetch linked repos from project (if project exists)
    linked_repos = None
    now_pre = __import__("datetime").datetime.now(
        __import__("datetime").UTC,
    ).isoformat()
    project_pre = get_or_create_project(
        config.db_path, req.repository, now_pre,
    )
    if project_pre.linked_repos:
        linked_repos = project_pre.linked_repos

    # Build extra context documents from governance docs + project context sources
    extra_documents = _build_extra_documents(config)
    if project_pre.context_sources:
        import json as _json
        ctx_src = project_pre.context_sources
        if isinstance(ctx_src, str):
            try:
                ctx_src = _json.loads(ctx_src)
            except Exception:
                ctx_src = []
        if isinstance(ctx_src, list):
            for src in ctx_src:
                if isinstance(src, dict) and src.get("key") and src.get("value"):
                    extra_documents.append(
                        f"Project context — {src['key']}: {src['value']}"
                    )

    try:
        result = await asyncio.to_thread(
            _run_pipeline, req.plan_data, req, linked_repos, extra_documents,
        )
    except Exception as e:
        logger.exception("Pipeline execution failed")
        raise HTTPException(
            status_code=500,
            detail=f"Assessment pipeline failed: {e}",
        ) from e

    # Create or get project
    now = result.timestamp.isoformat()
    project = get_or_create_project(config.db_path, req.repository, now)

    # Generate snapshot ID and plan hash
    snapshot_id = str(uuid.uuid4())
    plan_hash = hash_string(json.dumps(req.plan_data, sort_keys=True))

    # Save snapshot blob
    save_snapshot(config.snapshots_dir, snapshot_id, result)

    # Extract gate recommendation from change management agent
    cm_out = result.agent_results.get("change_management")
    gate = "pass"
    gate_justification = ""
    if cm_out and cm_out.output:
        out = cm_out.output
        if isinstance(out, dict):
            gate = out.get("gate_recommendation", "pass")
            gate_justification = out.get("gate_justification", "")
        else:
            gate = out.gate_recommendation
            gate_justification = out.gate_justification

    # Build metadata
    qs = result.quality_score
    finding_count = sum(qs.finding_counts.values())
    meta = SnapshotMeta(
        id=snapshot_id,
        project_id=project.id,
        commit_hash=req.commit_hash,
        created_at=now,
        plan_hash=plan_hash,
        score=qs.score,
        grade=qs.grade.value,
        finding_count=finding_count,
        critical_count=qs.finding_counts.get("CRITICAL", 0),
        high_count=qs.finding_counts.get("HIGH", 0),
        gate=gate,
        label=req.label,
    )
    insert_snapshot(config.db_path, meta)

    # Write audit trail
    from iac_risk.web.storage.database import AuditEntry, insert_audit_entry
    audit = AuditEntry(
        id=str(uuid.uuid4()),
        timestamp=now,
        snapshot_id=snapshot_id,
        commit_sha=req.commit_hash,
        repository=req.repository,
        changed_resources=json.dumps(
            _extract_changed_resources(result),
        ),
        compliance_outcomes=json.dumps(
            {"gate": gate, "score": qs.score, "grade": qs.grade.value}
        ),
        gate_recommendation=gate,
        gate_justification=gate_justification,
    )
    try:
        insert_audit_entry(config.db_path, audit)
    except Exception:
        logger.warning("Failed to write audit trail entry")

    # Auto-compare with previous snapshot for same plan
    comparison = None
    prev = get_previous_for_plan(config.db_path, plan_hash, snapshot_id)
    if prev:
        try:
            prev_result = load_snapshot(config.snapshots_dir, prev.id)
            diff = compare_snapshots(
                prev_result, result, prev.id, snapshot_id,
            )
            comparison = ComparisonSummary(
                previous_snapshot_id=prev.id,
                score_delta=diff.score_delta,
                new_finding_count=len(diff.new_findings),
                resolved_finding_count=len(diff.resolved_findings),
            )
        except Exception:
            logger.warning("Failed to compare with previous snapshot")

    logger.info(
        "Assessment complete: project=%s snapshot=%s score=%d",
        req.repository, snapshot_id, qs.score,
    )

    return AssessResponse(
        snapshot_id=snapshot_id,
        project_id=project.id,
        repository=req.repository,
        commit_hash=req.commit_hash,
        score=qs.score,
        grade=qs.grade.value,
        gate=gate,
        finding_count=finding_count,
        critical_count=qs.finding_counts.get("CRITICAL", 0),
        high_count=qs.finding_counts.get("HIGH", 0),
        comparison=comparison,
    )
