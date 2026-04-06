"""Snapshot and project listing, retrieval, comparison, and deletion."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from iac_risk.web.comparison import compare_snapshots
from iac_risk.web.config import WebConfig
from iac_risk.web.schemas import (
    ComparisonResult,
    ProjectSummary,
    SnapshotListResponse,
    SnapshotSummary,
)
from iac_risk.web.storage.database import (
    _connect,
    get_latest,
    get_snapshot,
    list_projects,
    list_snapshots,
)
from iac_risk.web.storage.database import (
    delete_snapshot as db_delete,
)
from iac_risk.web.storage.snapshot_store import (
    delete_snapshot_blob,
    load_snapshot,
    snapshot_exists,
)

router = APIRouter()


def _cfg(request: Request) -> WebConfig:
    return request.app.state.config


# --- Projects ---


@router.get("/projects/branches")
async def fetch_repo_branches(
    request: Request, repository: str = "",
) -> dict:
    """Fetch branches from a GitHub repository."""
    import json as _json
    import os
    import urllib.request

    if not repository:
        raise HTTPException(
            status_code=400, detail="repository is required",
        )

    # Strip URL formats to owner/repo
    repo = repository.strip()
    repo = repo.replace("https://github.com/", "")
    repo = repo.replace("http://github.com/", "")
    repo = repo.replace("github.com/", "")
    repo = repo.rstrip("/").removesuffix(".git")

    token = os.environ.get("GITHUB_TOKEN", "")
    url = f"https://api.github.com/repos/{repo}/branches?per_page=100"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    if token:
        req.add_header("Authorization", f"token {token}")

    branches = ["main", "master"]
    error = ""
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read())
        branches = [b["name"] for b in data]
    except Exception as e:
        error = str(e)

    # Detect terraform directory from repo tree
    terraform_dir = ""
    default_branch = branches[0] if branches else "main"
    try:
        tree_url = (
            f"https://api.github.com/repos/{repo}"
            f"/git/trees/{default_branch}?recursive=1"
        )
        tree_req = urllib.request.Request(tree_url)
        tree_req.add_header(
            "Accept", "application/vnd.github.v3+json",
        )
        if token:
            tree_req.add_header("Authorization", f"token {token}")
        with urllib.request.urlopen(tree_req, timeout=10) as resp:
            tree_data = _json.loads(resp.read())
        tf_dirs: set[str] = set()
        for item in tree_data.get("tree", []):
            path = item.get("path", "")
            if path.endswith(".tf"):
                parts = path.rsplit("/", 1)
                tf_dir = parts[0] if len(parts) > 1 else "."
                tf_dirs.add(tf_dir)
        # Pick the shortest (most likely root tf dir)
        if tf_dirs:
            terraform_dir = min(tf_dirs, key=len)
    except Exception:
        pass

    result: dict = {
        "repository": repo,
        "branches": branches,
        "terraform_dir": terraform_dir,
    }
    if error:
        result["error"] = error
    return result


@router.post("/projects")
async def create_project(request: Request) -> dict:
    """Create a new project with context sources."""
    import json as _json
    from datetime import UTC, datetime

    from iac_risk.web.storage.database import get_or_create_project

    config = _cfg(request)
    body = await request.json()
    repository = body.get("repository", "").strip()
    repository = repository.replace("https://github.com/", "").replace("http://github.com/", "").replace("github.com/", "").rstrip("/").removesuffix(".git")
    if not repository:
        raise HTTPException(
            status_code=400, detail="repository is required",
        )
    context_sources = body.get("context_sources", [])
    linked_repos = body.get("linked_repos", [])
    default_branch = body.get("default_branch", "main")
    terraform_dir = body.get("terraform_dir", "infra")
    server_url = body.get("server_url", "")

    now = datetime.now(UTC).isoformat()
    project = get_or_create_project(
        config.db_path, repository, now,
    )

    # Save context sources, linked repos, default branch
    conn = _connect(config.db_path)
    try:
        conn.execute(
            """UPDATE projects
               SET context_sources = ?, linked_repos = ?,
                   default_branch = ?, terraform_dir = ?,
                   server_url = ?
               WHERE id = ?""",
            (
                _json.dumps(context_sources),
                _json.dumps(linked_repos),
                default_branch,
                terraform_dir,
                server_url,
                project.id,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "id": project.id,
        "repository": repository,
        "context_sources": context_sources,
        "linked_repos": linked_repos,
    }


@router.get("/projects/{project_id}/detail")
async def get_project_detail(
    project_id: str, request: Request,
) -> dict:
    """Get full project details including context sources."""
    from iac_risk.web.storage.database import get_project

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )
    return {
        "id": project.id,
        "repository": project.repository,
        "context_sources": project.context_sources or [],
        "linked_repos": project.linked_repos or [],
        "default_branch": project.default_branch,
        "terraform_dir": project.terraform_dir,
        "server_url": project.server_url,
        "artifact_name": project.artifact_name,
        "workflow_filter": project.workflow_filter,
        "webhook_id": project.webhook_id,
    }


@router.put("/projects/{project_id}/settings")
async def update_project_settings(
    project_id: str, request: Request,
) -> dict:
    """Update project settings."""
    import json as _json

    from iac_risk.web.storage.database import get_project

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )

    body = await request.json()
    conn = _connect(config.db_path)
    try:
        updates = []
        params = []
        if "default_branch" in body:
            updates.append("default_branch = ?")
            params.append(body["default_branch"])
        if "terraform_dir" in body:
            updates.append("terraform_dir = ?")
            params.append(body["terraform_dir"])
        if "context_sources" in body:
            updates.append("context_sources = ?")
            params.append(_json.dumps(body["context_sources"]))
        if "linked_repos" in body:
            updates.append("linked_repos = ?")
            params.append(_json.dumps(body["linked_repos"]))
        if "server_url" in body:
            updates.append("server_url = ?")
            params.append(body["server_url"])
        if "artifact_name" in body:
            updates.append("artifact_name = ?")
            params.append(body["artifact_name"])
        if "workflow_filter" in body:
            updates.append("workflow_filter = ?")
            params.append(body["workflow_filter"])
        if updates:
            params.append(project_id)
            conn.execute(
                f"UPDATE projects SET {', '.join(updates)} "
                f"WHERE id = ?",
                params,
            )
            conn.commit()

        return {"status": "saved"}
    finally:
        conn.close()


@router.delete("/projects/{project_id}")
async def remove_project(
    project_id: str, request: Request,
) -> dict:
    """Delete a project and all its data."""
    from iac_risk.web.storage.database import (
        delete_project,
        get_project,
    )
    from iac_risk.web.storage.snapshot_store import delete_snapshot_blob

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )
    snapshots, _ = list_snapshots(
        config.db_path, project_id=project_id, limit=1000,
    )
    for s in snapshots:
        delete_snapshot_blob(config.snapshots_dir, s.id)
    delete_project(config.db_path, project_id)
    return {"deleted": project_id, "repository": project.repository}


@router.get("/projects", response_model=list[ProjectSummary])
async def get_projects(request: Request) -> list[ProjectSummary]:
    """List all projects with latest score and trend."""
    config = _cfg(request)
    projects = list_projects(config.db_path)
    result = []
    for p in projects:
        trend = ""
        if p.latest_score is not None and p.previous_score is not None:
            if p.latest_score > p.previous_score:
                trend = "up"
            elif p.latest_score < p.previous_score:
                trend = "down"
            else:
                trend = "flat"
        result.append(ProjectSummary(
            id=p.id,
            repository=p.repository,
            created_at=p.created_at,
            updated_at=p.updated_at,
            latest_score=p.latest_score,
            latest_grade=p.latest_grade,
            snapshot_count=p.snapshot_count,
            trend=trend,
        ))
    return result


@router.get(
    "/projects/{project_id}/snapshots",
    response_model=SnapshotListResponse,
)
async def get_project_snapshots(
    project_id: str, request: Request,
    offset: int = 0, limit: int = 20,
) -> SnapshotListResponse:
    """List snapshots for a specific project."""
    config = _cfg(request)
    snapshots, total = list_snapshots(
        config.db_path, project_id=project_id,
        offset=offset, limit=limit,
    )
    return SnapshotListResponse(
        snapshots=[_meta_to_summary(s) for s in snapshots],
        total=total, offset=offset, limit=limit,
    )


@router.put("/projects/{project_id}/linked-repos")
async def set_linked_repos(
    project_id: str, request: Request,
) -> dict:
    """Set linked repos for a project."""
    from iac_risk.web.storage.database import (
        get_project,
        update_linked_repos,
    )

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )
    body = await request.json()
    repos = body.get("linked_repos", [])
    update_linked_repos(config.db_path, project_id, repos)
    return {"project_id": project_id, "linked_repos": repos}


@router.get("/projects/{project_id}/linked-repos")
async def get_linked_repos(
    project_id: str, request: Request,
) -> dict:
    """Get linked repos for a project."""
    from iac_risk.web.storage.database import get_project

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )
    return {
        "project_id": project_id,
        "linked_repos": project.linked_repos or [],
    }


# --- Snapshots ---


@router.get("/snapshots/latest")
async def get_latest_snapshot(request: Request) -> dict:
    """Get the most recent snapshot (full PipelineResult)."""
    config = _cfg(request)
    meta = get_latest(config.db_path)
    if not meta:
        raise HTTPException(status_code=404, detail="No snapshots found")
    result = load_snapshot(config.snapshots_dir, meta.id)
    return result.model_dump()


@router.get("/snapshots", response_model=SnapshotListResponse)
async def list_all_snapshots(
    request: Request, offset: int = 0, limit: int = 20,
) -> SnapshotListResponse:
    """List stored snapshots, newest first."""
    config = _cfg(request)
    snapshots, total = list_snapshots(
        config.db_path, offset=offset, limit=limit,
    )
    return SnapshotListResponse(
        snapshots=[_meta_to_summary(s) for s in snapshots],
        total=total, offset=offset, limit=limit,
    )


@router.get("/snapshots/{snapshot_id}")
async def get_snapshot_detail(
    snapshot_id: str, request: Request,
) -> dict:
    """Get a specific snapshot (full PipelineResult)."""
    config = _cfg(request)
    meta = get_snapshot(config.db_path, snapshot_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    if not snapshot_exists(config.snapshots_dir, snapshot_id):
        raise HTTPException(
            status_code=404, detail="Snapshot data file missing",
        )
    result = load_snapshot(config.snapshots_dir, snapshot_id)
    return result.model_dump()


@router.get(
    "/snapshots/{snapshot_id}/compare/{other_id}",
    response_model=ComparisonResult,
)
async def compare(
    snapshot_id: str, other_id: str, request: Request,
) -> ComparisonResult:
    """Compare two snapshots."""
    config = _cfg(request)
    for sid in (snapshot_id, other_id):
        if not get_snapshot(config.db_path, sid):
            raise HTTPException(
                status_code=404, detail=f"Snapshot {sid} not found",
            )
    old_result = load_snapshot(config.snapshots_dir, other_id)
    new_result = load_snapshot(config.snapshots_dir, snapshot_id)
    return compare_snapshots(old_result, new_result, other_id, snapshot_id)


@router.delete("/snapshots/{snapshot_id}")
async def delete_snapshot(
    snapshot_id: str, request: Request,
) -> dict:
    """Delete a snapshot."""
    config = _cfg(request)
    meta = get_snapshot(config.db_path, snapshot_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    db_delete(config.db_path, snapshot_id)
    delete_snapshot_blob(config.snapshots_dir, snapshot_id)
    return {"deleted": snapshot_id}


# --- Snapshot Upload (CLI-direct mode) ---


@router.post("/snapshots/upload")
async def upload_snapshot(request: Request) -> dict:
    """Accept a pre-built PipelineResult from the CLI and store it."""
    import json as _json
    import uuid

    from iac_risk.core.schemas import PipelineResult
    from iac_risk.services.content_hash import hash_string
    from iac_risk.web.storage.database import (
        SnapshotMeta,
        get_or_create_project,
        get_previous_for_plan,
        insert_snapshot,
    )
    from iac_risk.web.storage.snapshot_store import save_snapshot

    config = _cfg(request)
    body = await request.json()

    repository = body.get("repository", "")
    commit_hash = body.get("commit_hash", "")
    label = body.get("label", "")
    result_data = body.get("result")

    if not repository:
        raise HTTPException(
            status_code=400, detail="repository is required",
        )
    if not result_data:
        raise HTTPException(
            status_code=400, detail="result is required",
        )

    try:
        result = PipelineResult.model_validate(result_data)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid PipelineResult: {e}",
        ) from e

    # Create or get project
    from datetime import UTC, datetime
    now = datetime.now(UTC).isoformat()
    project = get_or_create_project(config.db_path, repository, now)

    # Store snapshot
    snapshot_id = str(uuid.uuid4())
    plan_hash = hash_string(
        result.plan_file_hash or _json.dumps(
            result_data, sort_keys=True,
        )[:10000],
    )
    save_snapshot(config.snapshots_dir, snapshot_id, result)

    # Extract gate from change management
    cm_out = result.agent_results.get("change_management")
    gate = "pass"
    if cm_out and cm_out.output:
        out = cm_out.output
        gate = (
            out.get("gate_recommendation", "pass")
            if isinstance(out, dict)
            else out.gate_recommendation
        )

    qs = result.quality_score
    finding_count = sum(qs.finding_counts.values())
    meta = SnapshotMeta(
        id=snapshot_id,
        project_id=project.id,
        commit_hash=commit_hash,
        created_at=now,
        plan_hash=plan_hash,
        score=qs.score,
        grade=qs.grade.value,
        finding_count=finding_count,
        critical_count=qs.finding_counts.get("CRITICAL", 0),
        high_count=qs.finding_counts.get("HIGH", 0),
        gate=gate,
        label=label,
    )
    insert_snapshot(config.db_path, meta)

    # Comparison with previous
    comparison = None
    prev = get_previous_for_plan(config.db_path, plan_hash, snapshot_id)
    if prev:
        try:
            prev_result = load_snapshot(config.snapshots_dir, prev.id)
            diff = compare_snapshots(
                prev_result, result, prev.id, snapshot_id,
            )
            comparison = {
                "previous_snapshot_id": prev.id,
                "score_delta": diff.score_delta,
                "new_findings": len(diff.new_findings),
                "resolved_findings": len(diff.resolved_findings),
            }
        except Exception:
            pass

    return {
        "snapshot_id": snapshot_id,
        "project_id": project.id,
        "repository": repository,
        "commit_hash": commit_hash,
        "score": qs.score,
        "grade": qs.grade.value,
        "gate": gate,
        "finding_count": finding_count,
        "critical_count": qs.finding_counts.get("CRITICAL", 0),
        "comparison": comparison,
    }


# --- CI Integration Snippets ---


def _generate_push_snippet(
    terraform_dir: str,
    server_url: str,
) -> str:
    """Generate push-mode snippet (steps to paste into existing workflow)."""
    return f"""# Add these steps after your 'terraform plan' step:

- name: Export Plan JSON
  working-directory: {terraform_dir}
  run: terraform show -json plan.out > plan.json

- name: Pro-Prowler Assessment
  id: prowler
  continue-on-error: true
  run: |
    RESPONSE=$(curl -s --max-time 300 \\
      -X POST \\
      -H "Content-Type: application/json" \\
      -d "{{\\
        \\"plan_data\\": $(cat {terraform_dir}/plan.json),\\
        \\"repository\\": \\"${{{{ github.repository }}}}\\",\\
        \\"commit_hash\\": \\"${{{{ github.sha }}}}\\"\\
      }}" \\
      {server_url}/api/assess)

    if [ -z "$RESPONSE" ]; then
      echo "::warning::Pro-Prowler server did not respond"
      exit 0
    fi

    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"

    SCORE=$(echo "$RESPONSE" | jq -r '.score' 2>/dev/null)
    GRADE=$(echo "$RESPONSE" | jq -r '.grade' 2>/dev/null)
    GATE=$(echo "$RESPONSE" | jq -r '.gate' 2>/dev/null)
    FINDINGS=$(echo "$RESPONSE" | jq -r '.finding_count' 2>/dev/null)
    CRITICAL=$(echo "$RESPONSE" | jq -r '.critical_count' 2>/dev/null)
    SNAPSHOT=$(echo "$RESPONSE" | jq -r '.snapshot_id' 2>/dev/null)

    echo "score=${{SCORE}}" >> $GITHUB_OUTPUT
    echo "gate=${{GATE}}" >> $GITHUB_OUTPUT

    echo "## Pro-Prowler Risk Assessment" >> $GITHUB_STEP_SUMMARY
    echo "- **Score**: ${{SCORE}}/100 (Grade ${{GRADE}})" >> $GITHUB_STEP_SUMMARY
    echo "- **Gate**: ${{GATE}}" >> $GITHUB_STEP_SUMMARY
    echo "- **Findings**: ${{FINDINGS}} total, ${{CRITICAL}} critical" >> $GITHUB_STEP_SUMMARY
    echo "- [Dashboard]({server_url}/dashboard/snapshots/${{SNAPSHOT}})" >> $GITHUB_STEP_SUMMARY

- name: Gate Check
  if: always()
  run: |
    SCORE="${{{{ steps.prowler.outputs.score }}}}"
    GATE="${{{{ steps.prowler.outputs.gate }}}}"
    if [ -z "$SCORE" ] || [ "$SCORE" = "null" ]; then
      echo "::warning::Pro-Prowler: Assessment did not return results"
    elif [ "$GATE" = "block" ] || [ "$SCORE" -lt 60 ]; then
      echo "::warning::Pro-Prowler: WARNING (score $SCORE, gate $GATE)"
    else
      echo "Pro-Prowler: PASSED (score $SCORE, gate $GATE)"
    fi"""


def _generate_pull_snippet(
    terraform_dir: str,
    artifact_name: str,
) -> str:
    """Generate pull-mode snippet (upload artifact for webhook consumption)."""
    return f"""# Add these steps after your 'terraform plan' step:

- name: Export Plan JSON
  working-directory: {terraform_dir}
  run: terraform show -json plan.out > plan.json

- name: Upload Plan for Pro-Prowler
  uses: actions/upload-artifact@v4
  with:
    name: {artifact_name}
    path: {terraform_dir}/plan.json
    retention-days: 3"""


@router.get("/projects/{project_id}/snippets")
async def get_project_snippets(
    project_id: str, request: Request,
) -> dict:
    """Generate CI integration snippets for a project."""
    from iac_risk.web.storage.database import (
        get_all_settings,
        get_project,
    )

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )

    server_url = project.server_url
    if not server_url:
        settings = get_all_settings(config.db_path)
        server_url = settings.get("server_url", "")
    if not server_url or server_url == "http://localhost:8000":
        server_url = str(request.base_url).rstrip("/")
    tf_dir = project.terraform_dir or "infra"
    artifact_name = project.artifact_name or "terraform-plan"

    is_public = server_url and "localhost" not in server_url

    return {
        "repository": project.repository,
        "terraform_dir": tf_dir,
        "server_url": server_url,
        "artifact_name": artifact_name,
        "webhook_id": project.webhook_id,
        "is_public_server": is_public,
        "push_snippet": _generate_push_snippet(tf_dir, server_url),
        "pull_snippet": _generate_pull_snippet(tf_dir, artifact_name),
    }


# --- Criticality Overrides ---


@router.post("/projects/{project_id}/overrides")
async def save_override(
    project_id: str, request: Request,
) -> dict:
    """Save a criticality override for a resource."""
    import uuid
    from datetime import UTC, datetime

    from iac_risk.web.storage.database import (
        CriticalityOverride,
        get_project,
        upsert_criticality_override,
    )

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(
            status_code=404, detail="Project not found",
        )

    body = await request.json()
    override = CriticalityOverride(
        id=str(uuid.uuid4()),
        project_id=project_id,
        resource_address=body.get("resource_address", ""),
        criticality=body.get("criticality", "MODERATE"),
        data_classification=body.get(
            "data_classification", "internal",
        ),
        compliance_scope=body.get("compliance_scope", []),
        notes=body.get("notes", ""),
        updated_by=body.get("updated_by", ""),
        updated_at=datetime.now(UTC).isoformat(),
    )
    upsert_criticality_override(config.db_path, override)
    return {"status": "saved", "resource_address": override.resource_address}


@router.get("/projects/{project_id}/overrides")
async def list_overrides(
    project_id: str, request: Request,
) -> dict:
    """Get all criticality overrides for a project."""
    from iac_risk.web.storage.database import (
        get_criticality_overrides,
    )

    config = _cfg(request)
    overrides = get_criticality_overrides(
        config.db_path, project_id,
    )
    return {
        "overrides": {
            addr: {
                "criticality": o.criticality,
                "data_classification": o.data_classification,
                "compliance_scope": o.compliance_scope,
                "notes": o.notes,
                "updated_at": o.updated_at,
            }
            for addr, o in overrides.items()
        }
    }


# --- Risk Comments ---


@router.post("/snapshots/{snapshot_id}/comments")
async def add_risk_comment(
    snapshot_id: str, request: Request,
) -> dict:
    """Add a risk comment/acceptance for a resource."""
    import uuid
    from datetime import UTC, datetime

    from iac_risk.web.storage.database import (
        RiskComment,
        upsert_risk_comment,
    )

    config = _cfg(request)
    meta = get_snapshot(config.db_path, snapshot_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    body = await request.json()
    rc = RiskComment(
        id=str(uuid.uuid4()),
        project_id=meta.project_id,
        resource_address=body.get("resource_address", ""),
        comment=body.get("comment", ""),
        accepted=body.get("accepted", False),
        expiry_date=body.get("expiry_date", ""),
        approver=body.get("approver", ""),
        created_at=datetime.now(UTC).isoformat(),
        snapshot_id=snapshot_id,
    )
    upsert_risk_comment(config.db_path, rc)
    return {"id": rc.id, "status": "saved"}


@router.get("/snapshots/{snapshot_id}/comments")
async def get_comments(
    snapshot_id: str, request: Request,
) -> list[dict]:
    """Get risk comments for a snapshot's project."""
    from iac_risk.web.storage.database import (
        get_risk_comments,
    )

    config = _cfg(request)
    meta = get_snapshot(config.db_path, snapshot_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    comments = get_risk_comments(config.db_path, meta.project_id)
    return [
        {
            "id": c.id,
            "resource_address": c.resource_address,
            "comment": c.comment,
            "accepted": c.accepted,
            "expiry_date": c.expiry_date,
            "approver": c.approver,
            "created_at": c.created_at,
        }
        for c in comments
    ]


def _meta_to_summary(meta: object) -> SnapshotSummary:
    return SnapshotSummary(
        id=meta.id,  # type: ignore[attr-defined]
        project_id=meta.project_id,  # type: ignore[attr-defined]
        commit_hash=meta.commit_hash,  # type: ignore[attr-defined]
        created_at=meta.created_at,  # type: ignore[attr-defined]
        plan_hash=meta.plan_hash,  # type: ignore[attr-defined]
        score=meta.score,  # type: ignore[attr-defined]
        grade=meta.grade,  # type: ignore[attr-defined]
        finding_count=meta.finding_count,  # type: ignore[attr-defined]
        critical_count=meta.critical_count,  # type: ignore[attr-defined]
        high_count=meta.high_count,  # type: ignore[attr-defined]
        label=meta.label,  # type: ignore[attr-defined]
    )
