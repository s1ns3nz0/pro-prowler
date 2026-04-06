"""GitHub webhook receiver and CI integration endpoints."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request

from iac_risk.web.config import WebConfig
from iac_risk.web.storage.database import (
    SnapshotMeta,
    get_or_create_project,
    get_previous_for_plan,
    get_project,
    insert_snapshot,
)
from iac_risk.web.storage.snapshot_store import load_snapshot, save_snapshot

logger = logging.getLogger(__name__)
router = APIRouter()


def _cfg(request: Request) -> WebConfig:
    return request.app.state.config


def _github_token() -> str:
    return os.environ.get("GITHUB_TOKEN", "")


def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        secret.encode(), payload, hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def _find_project_for_repo(
    db_path, repo_full_name: str,
):
    """Find project matching the repository from webhook."""
    from iac_risk.web.storage.database import _connect, _row_to_project

    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM projects WHERE repository = ?",
            (repo_full_name,),
        ).fetchone()
        if row:
            return _row_to_project(row)
        return None
    finally:
        conn.close()


def _download_artifact(
    owner: str, repo: str, run_id: int, artifact_name: str,
) -> dict | None:
    """Download and extract a workflow run artifact via GitHub API."""
    import io
    import urllib.request
    import zipfile

    token = _github_token()
    if not token:
        logger.warning("No GITHUB_TOKEN — cannot download artifacts")
        return None

    # List artifacts for the run
    url = (
        f"https://api.github.com/repos/{owner}/{repo}"
        f"/actions/runs/{run_id}/artifacts"
    )
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        logger.warning("Failed to list artifacts: %s", e)
        return None

    # Find matching artifact
    artifact = None
    for a in data.get("artifacts", []):
        if a["name"] == artifact_name:
            artifact = a
            break

    if not artifact:
        logger.info(
            "No artifact '%s' in run %d", artifact_name, run_id,
        )
        return None

    # Download the artifact zip
    dl_url = artifact["archive_download_url"]
    req = urllib.request.Request(dl_url, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            zip_bytes = resp.read()
    except Exception as e:
        logger.warning("Failed to download artifact: %s", e)
        return None

    # Extract plan.json from zip
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        for name in zf.namelist():
            if name.endswith(".json"):
                return json.loads(zf.read(name))
        logger.warning("No JSON file in artifact zip")
        return None
    except Exception as e:
        logger.warning("Failed to extract artifact: %s", e)
        return None


def _get_latest_run(
    owner: str, repo: str, workflow_filter: str = "",
) -> dict | None:
    """Get the latest completed workflow run for a repo."""
    import urllib.request

    token = _github_token()
    if not token:
        return None

    url = (
        f"https://api.github.com/repos/{owner}/{repo}"
        f"/actions/runs?status=completed&per_page=10"
    )
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None

    for run in data.get("workflow_runs", []):
        if workflow_filter:
            run_path = run.get("path", "")
            if workflow_filter not in run_path:
                continue
        return run
    return None


def _run_assessment(
    plan_data: dict,
    repository: str,
    commit_hash: str,
    config: WebConfig,
) -> dict:
    """Run the assessment pipeline and store the snapshot."""
    from iac_risk.core.schemas import PipelineConfig
    from iac_risk.orchestrator.runner import PipelineRunner
    from iac_risk.services.content_hash import hash_string
    from iac_risk.services.prowler_catalog import ProwlerCatalog
    from iac_risk.web.comparison import compare_snapshots
    from iac_risk.web.routes.assess import _build_extra_documents

    # Get project for linked repos
    project = get_or_create_project(
        config.db_path, repository,
        datetime.now(UTC).isoformat(),
    )

    linked_repos = []
    if project.linked_repos:
        from iac_risk.core.schemas import LinkedRepo
        for r in project.linked_repos:
            if isinstance(r, dict):
                linked_repos.append(LinkedRepo(
                    repository=r.get("repository", ""),
                    repo_type=r.get("repo_type", "application"),
                ))
            elif isinstance(r, str):
                linked_repos.append(LinkedRepo(repository=r))

    extra_documents = _build_extra_documents(config)

    pipeline_config = PipelineConfig(
        skip_context_analysis=False,
        repository=repository,
        linked_repos=linked_repos,
        extra_documents=extra_documents,
    )
    catalog = ProwlerCatalog()
    runner = PipelineRunner(
        config=pipeline_config, plan_data=plan_data, catalog=catalog,
    )
    result = runner.run()

    # Store snapshot
    now = result.timestamp.isoformat()
    project = get_or_create_project(config.db_path, repository, now)
    snapshot_id = str(uuid.uuid4())
    plan_hash = hash_string(json.dumps(plan_data, sort_keys=True))
    save_snapshot(config.snapshots_dir, snapshot_id, result)

    # Extract gate
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
    )
    insert_snapshot(config.db_path, meta)

    # Comparison
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

    logger.info(
        "Webhook assessment complete: %s score=%d",
        repository, qs.score,
    )

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


# --- Webhook endpoint ---


@router.post("/webhooks/github")
async def github_webhook(request: Request) -> dict:
    """Receive GitHub workflow_run.completed webhook and run assessment."""
    config = _cfg(request)
    payload = await request.body()
    event = request.headers.get("X-GitHub-Event", "")

    if event == "ping":
        return {"status": "pong"}

    if event != "workflow_run":
        return {"status": "ignored", "reason": f"event={event}"}

    body = json.loads(payload)
    action = body.get("action")
    if action != "completed":
        return {"status": "ignored", "reason": f"action={action}"}

    # Extract repo info
    repo_data = body.get("repository", {})
    repo_full_name = repo_data.get("full_name", "")
    run_data = body.get("workflow_run", {})
    run_id = run_data.get("id")
    head_sha = run_data.get("head_sha", "")

    if not repo_full_name or not run_id:
        return {"status": "error", "reason": "missing repo or run_id"}

    # Find project
    project = _find_project_for_repo(config.db_path, repo_full_name)
    if not project:
        return {
            "status": "ignored",
            "reason": f"no project for {repo_full_name}",
        }

    # Verify webhook signature
    signature = request.headers.get("X-Hub-Signature-256", "")
    if project.webhook_secret:
        if not _verify_signature(payload, signature, project.webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid signature")

    # Check workflow filter
    if project.workflow_filter:
        run_path = run_data.get("path", "")
        if project.workflow_filter not in run_path:
            return {
                "status": "ignored",
                "reason": "workflow filter mismatch",
            }

    # Download artifact
    owner, repo = repo_full_name.split("/", 1)
    artifact_name = project.artifact_name or "terraform-plan"
    plan_data = _download_artifact(owner, repo, run_id, artifact_name)
    if not plan_data:
        return {
            "status": "ignored",
            "reason": f"no '{artifact_name}' artifact in run {run_id}",
        }

    # Run assessment in background thread
    try:
        result = await asyncio.to_thread(
            _run_assessment, plan_data, repo_full_name, head_sha, config,
        )
        return {"status": "assessed", **result}
    except Exception as e:
        logger.exception("Webhook assessment failed")
        return {"status": "error", "reason": str(e)}


# --- Register webhook ---


@router.post("/projects/{project_id}/register-webhook")
async def register_webhook(
    project_id: str, request: Request,
) -> dict:
    """Register a GitHub webhook for automatic assessment."""
    import urllib.request

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    token = _github_token()
    if not token:
        raise HTTPException(
            status_code=400,
            detail="GITHUB_TOKEN not configured on server",
        )

    # Determine webhook URL
    server_url = project.server_url
    if not server_url:
        from iac_risk.web.storage.database import get_all_settings
        settings = get_all_settings(config.db_path)
        server_url = settings.get("server_url", "")
    if not server_url or "localhost" in server_url:
        ct = request.headers.get("content-type", "")
        body = await request.json() if ct == "application/json" else {}
        server_url = body.get("server_url", "")
    if not server_url or "localhost" in server_url:
        raise HTTPException(
            status_code=400,
            detail="Server URL must be a public URL for webhooks. "
            "Set server_url in project settings.",
        )

    # Generate webhook secret
    webhook_secret = secrets.token_hex(32)

    # Register webhook on GitHub
    owner_repo = project.repository
    url = f"https://api.github.com/repos/{owner_repo}/hooks"
    hook_data = json.dumps({
        "name": "web",
        "active": True,
        "events": ["workflow_run"],
        "config": {
            "url": f"{server_url.rstrip('/')}/api/webhooks/github",
            "content_type": "json",
            "secret": webhook_secret,
            "insecure_ssl": "0",
        },
    }).encode()

    req = urllib.request.Request(
        url, data=hook_data, method="POST",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            hook = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        logger.warning("Webhook registration failed: %s %s", e.code, error_body)
        if e.code == 404:
            raise HTTPException(
                status_code=400,
                detail="Repository not found or token lacks permissions. "
                "Token needs admin:repo_hook scope.",
            ) from e
        if e.code == 422:
            raise HTTPException(
                status_code=400,
                detail="Webhook may already exist. Check repository settings.",
            ) from e
        raise HTTPException(
            status_code=500,
            detail=f"GitHub API error: {e.code}",
        ) from e

    # Store webhook ID and secret
    from iac_risk.web.storage.database import _connect
    conn = _connect(config.db_path)
    try:
        conn.execute(
            "UPDATE projects SET webhook_id = ?, webhook_secret = ? "
            "WHERE id = ?",
            (str(hook["id"]), webhook_secret, project_id),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info(
        "Webhook registered: %s hook_id=%s",
        project.repository, hook["id"],
    )

    return {
        "status": "registered",
        "webhook_id": hook["id"],
        "webhook_url": f"{server_url.rstrip('/')}/api/webhooks/github",
    }


# --- Manual sync ---


@router.post("/projects/{project_id}/sync")
async def sync_latest_run(
    project_id: str, request: Request,
) -> dict:
    """Manually fetch the latest workflow run artifact and run assessment."""
    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    owner, repo = project.repository.split("/", 1)
    artifact_name = project.artifact_name or "terraform-plan"

    # Find latest completed run
    run = _get_latest_run(owner, repo, project.workflow_filter)
    if not run:
        raise HTTPException(
            status_code=404,
            detail="No completed workflow runs found",
        )

    run_id = run["id"]
    head_sha = run.get("head_sha", "")

    # Download artifact
    plan_data = _download_artifact(owner, repo, run_id, artifact_name)
    if not plan_data:
        raise HTTPException(
            status_code=404,
            detail=f"No '{artifact_name}' artifact in latest run "
            f"(run #{run_id}). Add an upload-artifact step to "
            f"your workflow.",
        )

    # Run assessment
    try:
        result = await asyncio.to_thread(
            _run_assessment, plan_data, project.repository, head_sha, config,
        )
        return {"status": "assessed", "run_id": run_id, **result}
    except Exception as e:
        logger.exception("Sync assessment failed")
        raise HTTPException(
            status_code=500,
            detail=f"Assessment failed: {e}",
        ) from e


# --- Delete webhook ---


@router.delete("/projects/{project_id}/webhook")
async def delete_webhook(
    project_id: str, request: Request,
) -> dict:
    """Remove the GitHub webhook."""
    import urllib.request

    config = _cfg(request)
    project = get_project(config.db_path, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if not project.webhook_id:
        return {"status": "no_webhook"}

    token = _github_token()
    if token:
        url = (
            f"https://api.github.com/repos/{project.repository}"
            f"/hooks/{project.webhook_id}"
        )
        req = urllib.request.Request(url, method="DELETE", headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        })
        try:
            urllib.request.urlopen(req, timeout=15)
        except Exception as e:
            logger.warning("Failed to delete webhook: %s", e)

    # Clear from DB
    from iac_risk.web.storage.database import _connect
    conn = _connect(config.db_path)
    try:
        conn.execute(
            "UPDATE projects SET webhook_id = '', webhook_secret = '' "
            "WHERE id = ?",
            (project_id,),
        )
        conn.commit()
    finally:
        conn.close()

    return {"status": "deleted"}
