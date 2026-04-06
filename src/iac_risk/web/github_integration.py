"""GitHub integration — clone repos, modify HCL, create PRs."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def _github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN")


def _github_api(
    method: str, path: str, data: dict | None = None,
) -> dict:
    """Make a GitHub API request."""
    token = _github_token()
    if not token:
        raise RuntimeError("GITHUB_TOKEN not set")

    url = f"https://api.github.com{path}"
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    if body:
        req.add_header("Content-Type", "application/json")

    with urlopen(req) as resp:
        return json.loads(resp.read())


def clone_repo(repository: str, target_dir: Path) -> Path:
    """Clone a GitHub repository to a local directory."""
    token = _github_token()
    if token:
        url = f"https://x-access-token:{token}@github.com/{repository}.git"
    else:
        url = f"https://github.com/{repository}.git"

    subprocess.run(
        ["git", "clone", "--depth=1", url, str(target_dir)],
        check=True,
        capture_output=True,
    )
    return target_dir


def _find_tf_files(repo_dir: Path) -> list[Path]:
    """Find all .tf files in a repository."""
    return sorted(repo_dir.rglob("*.tf"))


def _apply_fixes_to_hcl(
    content: str,
    fixes: list[dict],
) -> str:
    """Apply attribute fixes to HCL content.

    Each fix has: resource_type, resource_name, attribute, old_value, new_value.
    Uses regex-based replacement for reliability.
    """
    result = content
    for fix in fixes:
        attr = fix["attribute"]
        old_val = fix["old_value"]
        new_val = fix["new_value"]

        # Build patterns for different value types
        if isinstance(old_val, bool):
            old_str = "true" if old_val else "false"
            new_str = "true" if new_val else "false"
        elif isinstance(old_val, (int, float)):
            old_str = str(old_val)
            new_str = str(new_val)
        elif isinstance(old_val, str):
            old_str = f'"{old_val}"'
            new_str = f'"{new_val}"'
        else:
            old_str = str(old_val)
            new_str = str(new_val)

        # Match: attribute = old_value (with flexible whitespace)
        pattern = rf'({re.escape(attr)}\s*=\s*){re.escape(old_str)}'
        replacement = rf'\g<1>{new_str}'
        result = re.sub(pattern, replacement, result)

    return result


def generate_fixes_for_findings(
    findings: list[dict],
) -> list[dict]:
    """Generate HCL attribute fixes from findings.

    Maps each finding's actual_value → expected_value for the
    relevant Terraform attribute.
    """
    fixes = []
    for f in findings:
        if f.get("actual_value") is None or f.get("expected_value") is None:
            continue

        # Derive attribute name from check_id patterns
        check_id = f.get("check_id", "")
        address = f.get("resource_address", "")
        parts = address.split(".")
        resource_name = parts[-1] if len(parts) > 1 else ""
        resource_type = f.get("resource_type", "")

        attr = _check_to_attribute(check_id)
        if not attr:
            continue

        fixes.append({
            "resource_type": resource_type,
            "resource_name": resource_name,
            "resource_address": address,
            "attribute": attr,
            "old_value": f["actual_value"],
            "new_value": f["expected_value"],
            "check_id": check_id,
            "title": f.get("title", ""),
            "remediation": f.get("remediation", ""),
        })

    return fixes


def _check_to_attribute(check_id: str) -> str:
    """Map a check ID to the Terraform attribute it evaluates."""
    mapping = {
        "rds_public_accessibility": "publicly_accessible",
        "rds_encryption_at_rest": "storage_encrypted",
        "rds_multi_az": "multi_az",
        "rds_backup_retention": "backup_retention_period",
        "ec2_imdsv2_required": "http_tokens",
        "ec2_ebs_encryption": "encrypted",
        "s3_bucket_acl_not_public": "acl",
        "ebs_default_encryption": "enabled",
        "kms_key_rotation": "enable_key_rotation",
        "cloudtrail_enabled": "enable_logging",
        "config_recorder_enabled": "is_enabled",
    }
    return mapping.get(check_id, "")


def apply_fixes_to_repo(
    repo_dir: Path,
    fixes: list[dict],
) -> list[dict]:
    """Apply fixes to .tf files in a cloned repo. Returns applied fixes."""
    tf_files = _find_tf_files(repo_dir)
    applied: list[dict] = []

    for tf_file in tf_files:
        content = tf_file.read_text()
        original = content

        # Filter fixes relevant to resources in this file
        file_fixes = []
        for fix in fixes:
            rtype = fix["resource_type"]
            rname = fix["resource_name"]
            # Check if this file contains the resource block
            pattern = rf'resource\s+"{rtype}"\s+"{rname}"'
            if re.search(pattern, content):
                file_fixes.append(fix)

        if file_fixes:
            content = _apply_fixes_to_hcl(content, file_fixes)
            if content != original:
                tf_file.write_text(content)
                applied.extend(file_fixes)

    return applied


def create_fix_branch(
    repo_dir: Path,
    branch_name: str,
) -> None:
    """Create and checkout a new branch."""
    subprocess.run(
        ["git", "checkout", "-b", branch_name],
        cwd=repo_dir, check=True, capture_output=True,
    )


def commit_fixes(
    repo_dir: Path,
    message: str,
) -> str:
    """Stage and commit changes. Returns commit hash."""
    subprocess.run(
        ["git", "add", "-A"],
        cwd=repo_dir, check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo_dir, check=True, capture_output=True,
    )
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_dir, check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def push_branch(repo_dir: Path, branch_name: str) -> None:
    """Push branch to remote."""
    subprocess.run(
        ["git", "push", "origin", branch_name],
        cwd=repo_dir, check=True, capture_output=True,
    )


def create_pull_request(
    repository: str,
    branch_name: str,
    title: str,
    body: str,
    base: str = "main",
) -> dict:
    """Create a pull request via GitHub API."""
    return _github_api("POST", f"/repos/{repository}/pulls", {
        "title": title,
        "body": body,
        "head": branch_name,
        "base": base,
    })


def _generate_impact_analysis(
    applied_fixes: list[dict],
) -> str:
    """Use AI to generate impact analysis of the changes."""
    from iac_risk.services.llm_client import call_llm

    changes_text = "\n".join(
        f"- {f['resource_address']}: {f['attribute']} "
        f"'{f['old_value']}' → '{f['new_value']}'"
        for f in applied_fixes
    )
    result = call_llm(
        "You are an infrastructure change analyst. "
        "Analyze the impact of these Terraform changes. "
        "For each change, note potential side effects or "
        "breaking changes. Be concise — 1-2 sentences per change.",
        f"Terraform attribute changes:\n{changes_text}",
        max_tokens=1024,
    )
    return result or "Impact analysis unavailable."


def build_pr_body(
    service: str,
    snapshot_id: str,
    applied_fixes: list[dict],
    change_review: dict | None = None,
    accepted_risks: list[dict] | None = None,
) -> str:
    """Build comprehensive PR with 6 sections."""
    lines = [
        "## IaC Risk Assessment — Change Report",
        "",
    ]

    # 1. Change Summary
    resources = set(f["resource_address"] for f in applied_fixes)
    lines.append("### Summary")
    lines.append(
        f"Remediates **{len(applied_fixes)} findings** "
        f"across **{len(resources)} resources** in {service}."
    )
    if accepted_risks:
        lines.append(
            f"{len(accepted_risks)} finding(s) accepted "
            f"with documented justification."
        )
    lines.append(f"\n**Snapshot**: `{snapshot_id[:12]}`")
    lines.append("")

    # 2. Before/After Changes
    lines.append("### Changes (Before → After)")
    lines.append("")
    lines.append(
        "| Resource | Attribute | Before | After |"
    )
    lines.append("| --- | --- | --- | --- |")
    for fix in applied_fixes:
        lines.append(
            f"| `{fix['resource_address']}` | "
            f"`{fix['attribute']}` | "
            f"`{fix['old_value']}` | "
            f"`{fix['new_value']}` |"
        )
    lines.append("")

    # 3. Impact Analysis (AI)
    lines.append("### Impact Analysis")
    lines.append("")
    impact = _generate_impact_analysis(applied_fixes)
    lines.append(impact)
    lines.append("")

    # 4. Compliance Impact
    if change_review:
        entries = change_review.get("change_entries", [])
        all_controls: set[str] = set()
        for e in entries:
            for c in e.get("affected_controls", []):
                all_controls.add(c)
        if all_controls:
            lines.append("### Compliance Impact")
            lines.append("")
            by_fw: dict[str, list[str]] = {}
            for ctrl in sorted(all_controls):
                parts = ctrl.split(":", 1)
                fw = parts[0] if len(parts) > 1 else "Other"
                cid = parts[1] if len(parts) > 1 else ctrl
                by_fw.setdefault(fw, []).append(cid)
            for fw, cids in sorted(by_fw.items()):
                lines.append(
                    f"- **{fw}**: {', '.join(cids)}"
                )
            lines.append("")

    # 5. Accepted Risks
    if accepted_risks:
        lines.append("### Accepted Risks")
        lines.append("")
        for ar in accepted_risks:
            addr = ar.get("resource_address", "")
            comment = ar.get("comment", "")
            expiry = ar.get("expiry_date", "")
            lines.append(
                f"- `{addr}`: {comment}"
            )
            if expiry:
                lines.append(f"  - Expires: {expiry}")
        lines.append("")

    # 6. Rollback Plan
    if change_review:
        entries = change_review.get("change_entries", [])
        if entries:
            lines.append("### Rollback Plan")
            lines.append("")
            for entry in entries:
                addr = entry.get("resource_address", "")
                steps = entry.get("rollback_steps", [])
                if steps:
                    lines.append(f"**`{addr}`**")
                    for step in steps:
                        lines.append(f"1. {step}")
                    lines.append("")

    lines.append("---")
    lines.append(
        "*Generated by IaC Risk Assessment*"
    )

    return "\n".join(lines)


def execute_fix(
    repository: str,
    service: str,
    snapshot_id: str,
    findings: list[dict],
    change_review: dict | None = None,
    accepted_risks: list[dict] | None = None,
    base_branch: str = "main",
) -> dict:
    """Full fix flow: clone → fix → branch → commit → push → PR.

    Returns dict with pr_url, branch, fixes_applied.
    """
    if not _github_token():
        raise RuntimeError(
            "GITHUB_TOKEN environment variable is required "
            "for creating fix PRs"
        )

    fixes = generate_fixes_for_findings(findings)
    if not fixes:
        return {
            "error": "No auto-fixable findings for this service",
            "fixes_applied": 0,
        }

    work_dir = Path(tempfile.mkdtemp(prefix="iac-fix-"))
    try:
        # Clone
        repo_dir = clone_repo(repository, work_dir / "repo")

        # Apply fixes
        applied = apply_fixes_to_repo(repo_dir, fixes)
        if not applied:
            return {
                "error": "Fixes generated but no matching .tf files found",
                "fixes_applied": 0,
            }

        # Branch, commit, push
        branch = (
            f"fix/pro-prowler/{service.lower()}-{snapshot_id[:8]}"
        )
        create_fix_branch(repo_dir, branch)
        commit_fixes(
            repo_dir,
            f"fix({service.lower()}): remediate "
            f"{len(applied)} findings from IaC risk assessment",
        )
        push_branch(repo_dir, branch)

        # Create PR
        pr_body = build_pr_body(
            service, snapshot_id, applied,
            change_review, accepted_risks,
        )
        pr = create_pull_request(
            repository,
            branch,
            f"fix({service}): Remediate {len(applied)} "
            f"security findings",
            pr_body,
            base=base_branch,
        )

        return {
            "pr_url": pr.get("html_url", ""),
            "pr_number": pr.get("number"),
            "branch": branch,
            "fixes_applied": len(applied),
            "fixes": applied,
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
