"""Web-specific request/response Pydantic models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AssessRequest(BaseModel):
    plan_data: dict[str, Any] = Field(description="Terraform plan JSON")
    repository: str = Field(description="Repository name, e.g. org/repo")
    commit_hash: str = Field(default="", description="Git commit hash")
    label: str = ""
    skip_context_analysis: bool = False
    fail_threshold: int = 60


class ComparisonSummary(BaseModel):
    previous_snapshot_id: str
    score_delta: int
    new_finding_count: int
    resolved_finding_count: int


class AssessResponse(BaseModel):
    snapshot_id: str
    project_id: str
    repository: str
    commit_hash: str
    score: int
    grade: str
    gate: str = "pass"
    finding_count: int
    critical_count: int
    high_count: int
    comparison: ComparisonSummary | None = None


class ProjectSummary(BaseModel):
    id: str
    repository: str
    created_at: str
    updated_at: str
    latest_score: int | None = None
    latest_grade: str | None = None
    snapshot_count: int = 0
    trend: str = ""  # "up", "down", "flat", ""


class SnapshotSummary(BaseModel):
    id: str
    project_id: str
    commit_hash: str
    created_at: str
    plan_hash: str
    score: int
    grade: str
    finding_count: int
    critical_count: int
    high_count: int
    label: str


class SnapshotListResponse(BaseModel):
    snapshots: list[SnapshotSummary]
    total: int
    offset: int
    limit: int


class FindingSummary(BaseModel):
    check_id: str
    resource_address: str
    severity: str
    title: str


class ComplianceDelta(BaseModel):
    framework: str
    old_coverage: float
    new_coverage: float
    delta: float


class ComparisonResult(BaseModel):
    old_snapshot_id: str
    new_snapshot_id: str
    old_score: int
    new_score: int
    score_delta: int
    old_grade: str
    new_grade: str
    grade_changed: bool
    new_findings: list[FindingSummary]
    resolved_findings: list[FindingSummary]
    persistent_findings: list[FindingSummary]
    compliance_deltas: list[ComplianceDelta]
