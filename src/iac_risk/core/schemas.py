"""Core Pydantic schemas for all agent I/O contracts."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from iac_risk.core.enums import (
    AgentStatus,
    ComplianceFramework,
    ControlStatus,
    DetectionOperator,
    LetterGrade,
    ResourceAction,
    RiskLevel,
    Severity,
    ThreatSource,
)

# ---------------------------------------------------------------------------
# Core domain types
# ---------------------------------------------------------------------------


class InCodeRiskAcceptance(BaseModel):
    """Risk acceptance annotation parsed from Terraform HCL comments."""

    controls: list[str] = Field(
        default_factory=list,
        description="Accepted control IDs, e.g. ['PCI_DSS:1.3.1']",
    )
    reason: str = ""
    approver: str = ""
    expires: str = ""


class ResourceChange(BaseModel):
    """A single resource change from a Terraform plan."""

    address: str = Field(
        description="Full resource address, e.g. aws_s3_bucket.my_bucket",
    )
    resource_type: str = Field(
        description="Resource type, e.g. aws_s3_bucket",
    )
    provider: str = Field(
        description="Provider name",
    )
    action: ResourceAction
    before_config: dict[str, Any] | None = Field(
        default=None, description="Resource config before change",
    )
    after_config: dict[str, Any] | None = Field(
        default=None, description="Resource config after change",
    )
    after_unknown: dict[str, Any] = Field(
        default_factory=dict,
        description="Values not yet computed at plan time",
    )
    module_address: str | None = Field(
        default=None, description="Module path if in a module",
    )
    risk_acceptance: InCodeRiskAcceptance | None = Field(
        default=None,
        description="Risk acceptance from @risk- HCL comments",
    )


class ResourceInventory(BaseModel):
    """Normalized inventory of all resources from an IaC plan."""

    resources: list[ResourceChange] = Field(default_factory=list)
    terraform_version: str = ""
    format_version: str = ""


class DetectionLogic(BaseModel):
    """Declarative detection logic for a Prowler check."""

    field_path: str = Field(description="Dot-separated path into resource config")
    operator: DetectionOperator = DetectionOperator.EQUALS
    expected_value: Any = None
    sub_resource_type: str | None = Field(
        default=None,
        description="If check requires a sub-resource (modern AWS provider pattern)",
    )
    sub_resource_link_field: str = Field(
        default="bucket",
        description="Field in sub-resource config that references the parent",
    )
    legacy_field_path: str | None = Field(
        default=None, description="Fallback path for legacy single-resource pattern"
    )
    legacy_expected_value: Any = None


class AttackScenario(BaseModel):
    """A specific attack scenario derived from real-world threat intelligence."""

    technique: str = Field(description="Attack technique name")
    description: str = Field(
        description="Realistic 2-3 sentence attack narrative",
    )
    mitre_tactic: str = Field(
        default="",
        description="MITRE ATT&CK tactic, e.g. 'Credential Access (TA0006)'",
    )
    impact: str = Field(
        default="", description="What the attacker gains",
    )
    threat_source: ThreatSource = ThreatSource.ADVERSARIAL


class ProwlerCheckDef(BaseModel):
    """Definition of a Prowler-derived misconfiguration check."""

    check_id: str
    title: str
    description: str
    severity: Severity
    resource_types: list[str]
    detection_logic: DetectionLogic
    remediation: str = ""
    compliance_mappings: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Mapping of ComplianceFramework value -> list of control IDs",
    )
    attack_scenarios: list[AttackScenario] = Field(
        default_factory=list,
        description="Real-world attack scenarios that exploit this misconfiguration",
    )


class Finding(BaseModel):
    """A misconfiguration finding produced by the Cloud Misconfiguration Agent."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    check_id: str = Field(description="Prowler check ID that produced this finding")
    resource_address: str
    resource_type: str = ""
    severity: Severity
    title: str
    description: str
    actual_value: Any = None
    expected_value: Any = None
    remediation: str = ""
    compliance_controls: list[str] = Field(
        default_factory=list,
        description="Flattened list of compliance control IDs affected",
    )
    attack_scenarios: list[AttackScenario] = Field(
        default_factory=list,
        description="Attack scenarios from check definition",
    )


class ThreatEvent(BaseModel):
    """A NIST SP 800-30 threat event associated with a finding."""

    threat_source: ThreatSource
    event_description: str
    relevance: str = Field(
        default="",
        description="Why this threat is relevant to the finding",
    )
    mitre_tactic: str = Field(
        default="", description="MITRE ATT&CK tactic reference",
    )
    attack_technique: str = Field(
        default="", description="Specific attack technique name",
    )


class Vulnerability(BaseModel):
    """A vulnerability or predisposing condition identified per NIST SP 800-30."""

    description: str
    predisposing_conditions: list[str] = Field(default_factory=list)


class RiskDetermination(BaseModel):
    """NIST SP 800-30 risk determination for a finding."""

    finding_id: str
    threat_events: list[ThreatEvent] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    likelihood: RiskLevel = RiskLevel.MODERATE
    risk_level: int = Field(
        default=0, ge=0, le=25, description="Likelihood × Impact (1-25), set after impact"
    )
    risk_severity: Severity = Severity.MODERATE


class BusinessContext(BaseModel):
    """AI-derived business context for a resource pattern."""

    resource_pattern: str = Field(description="Glob pattern matching resource addresses")
    asset_criticality: RiskLevel = RiskLevel.MODERATE
    data_classification: str = Field(
        default="internal",
        description="public/internal/confidential/restricted",
    )
    compliance_scope: list[ComplianceFramework] = Field(default_factory=list)
    notes: str = ""


class ImpactRating(BaseModel):
    """Impact rating for a finding, incorporating business context."""

    finding_id: str
    mission_impact: RiskLevel = RiskLevel.MODERATE
    asset_impact: RiskLevel = RiskLevel.MODERATE
    individual_impact: RiskLevel = RiskLevel.LOW
    organizational_impact: RiskLevel = RiskLevel.MODERATE
    overall_impact: RiskLevel = RiskLevel.MODERATE
    business_context_annotation: str | None = None
    final_risk_level: int = Field(
        default=0, ge=0, le=25, description="Likelihood × overall_impact"
    )
    final_risk_severity: Severity = Severity.MODERATE


class ComplianceControl(BaseModel):
    """Status of a single compliance control."""

    framework: ComplianceFramework
    control_id: str
    control_title: str = ""
    status: ControlStatus = ControlStatus.UNMAPPED
    related_finding_ids: list[str] = Field(default_factory=list)
    context_annotation: str | None = None


class ComplianceGapAnalysis(BaseModel):
    """Compliance gap analysis for a single framework."""

    framework: ComplianceFramework
    controls: list[ComplianceControl] = Field(default_factory=list)
    coverage_score: float = Field(default=0.0, ge=0.0, le=100.0)
    passing_count: int = 0
    failing_count: int = 0
    unmapped_count: int = 0
    total_count: int = 0


class QualityScore(BaseModel):
    """Aggregate quality score for the assessment."""

    score: int = Field(default=100, ge=0, le=100)
    grade: LetterGrade = LetterGrade.A
    finding_counts: dict[str, int] = Field(default_factory=dict)
    compliance_coverage: dict[str, float] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Agent I/O contracts
# ---------------------------------------------------------------------------


class DetectedTool(BaseModel):
    """An IaC or app tool detected in the repository."""

    name: str = Field(description="e.g., terraform, terragrunt, cloudformation")
    paths: list[str] = Field(default_factory=list)
    assessed: bool = Field(
        default=False, description="Whether this tool is assessed",
    )


class DetectedEnvironment(BaseModel):
    """An environment detected in the repository."""

    name: str = Field(description="e.g., prod, staging, dev")
    path: str = ""


class AppInsight(BaseModel):
    """Business context derived from application config files."""

    repo: str = ""
    tech_stack: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    data_indicators: list[str] = Field(
        default_factory=list,
        description="Hints about data types: payment, PII, health",
    )
    description: str = ""


class GovernanceInsight(BaseModel):
    """Context from governance/policy documents."""

    repo: str = ""
    documents_found: list[str] = Field(default_factory=list)
    data_classification_rules: list[str] = Field(
        default_factory=list,
    )
    compliance_scope_rules: list[str] = Field(
        default_factory=list,
    )
    security_policies: list[str] = Field(default_factory=list)
    raw_content_summary: str = ""


class RepoAnalysis(BaseModel):
    """Output from the Repository Analysis Agent."""

    repository: str = ""
    structure_summary: str = ""
    detected_tools: list[DetectedTool] = Field(
        default_factory=list,
    )
    environments: list[DetectedEnvironment] = Field(
        default_factory=list,
    )
    app_insights: list[AppInsight] = Field(default_factory=list)
    governance_insights: list[GovernanceInsight] = Field(
        default_factory=list,
    )
    config_files_read: list[str] = Field(default_factory=list)


class LinkedRepo(BaseModel):
    """A linked repository with type classification."""

    repository: str
    repo_type: str = Field(
        default="application",
        description="'application' or 'governance'",
    )


class RepoAnalysisInput(BaseModel):
    repository: str = ""
    linked_repos: list[LinkedRepo] = Field(default_factory=list)


class RepoAnalysisOutput(BaseModel):
    analysis: RepoAnalysis = Field(default_factory=RepoAnalysis)


class IaCParserInput(BaseModel):
    plan_data: dict[str, Any] = Field(
        description="Raw Terraform plan JSON",
    )


class IaCParserOutput(BaseModel):
    inventory: ResourceInventory


class CloudMisconfigInput(BaseModel):
    inventory: ResourceInventory


class CloudMisconfigOutput(BaseModel):
    findings: list[Finding] = Field(default_factory=list)


class ContextAnalysisInput(BaseModel):
    business_docs_dir: Path | None = None
    cache_dir: Path = Path(".pro-prowler-cache")
    app_insights: list[AppInsight] = Field(default_factory=list)
    governance_insights: list[GovernanceInsight] = Field(
        default_factory=list,
    )
    extra_documents: list[str] = Field(
        default_factory=list,
        description="Pre-built context strings from governance docs, context sources, etc.",
    )


class ContextAnalysisOutput(BaseModel):
    contexts: list[BusinessContext] = Field(default_factory=list)
    cache_hit: bool = False
    document_hash: str = ""


class AttackPath(BaseModel):
    """AI-generated chained attack path for a specific resource."""

    resource_address: str
    resource_type: str
    service_category: str = Field(
        description="AWS service category: S3, EC2, RDS, IAM, VPC, etc.",
    )
    finding_ids: list[str] = Field(default_factory=list)
    attack_narrative: str = Field(
        description="AI-generated chained attack description",
    )
    risk_summary: str = Field(
        default="", description="One-line risk summary",
    )
    fingerprint: str = Field(
        default="", description="Cache key for this resource+findings combo",
    )


class RiskAnalysisInput(BaseModel):
    inventory: ResourceInventory
    findings: list[Finding] = Field(default_factory=list)
    business_contexts: list[BusinessContext] = Field(default_factory=list)


class RiskAnalysisOutput(BaseModel):
    risk_determinations: list[RiskDetermination] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)


class ImpactAssessmentInput(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    risk_determinations: list[RiskDetermination] = Field(default_factory=list)
    business_contexts: list[BusinessContext] = Field(default_factory=list)


class ImpactAssessmentOutput(BaseModel):
    impact_ratings: list[ImpactRating] = Field(default_factory=list)


class ComplianceMappingInput(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    impact_ratings: list[ImpactRating] = Field(default_factory=list)
    business_contexts: list[BusinessContext] = Field(default_factory=list)
    frameworks: list[ComplianceFramework] = Field(
        default_factory=lambda: list(ComplianceFramework)
    )


class ComplianceMappingOutput(BaseModel):
    gap_analyses: list[ComplianceGapAnalysis] = Field(default_factory=list)


class ChangeRiskEntry(BaseModel):
    """Compliance risk assessment for a single resource change."""

    resource_address: str
    resource_type: str
    change_type: str = Field(
        description="create, update, destroy, or replace",
    )
    affected_controls: list[str] = Field(
        default_factory=list,
        description="Control IDs affected, e.g. 'PCI_DSS:6.5.1'",
    )
    gate_recommendation: str = Field(
        default="pass", description="pass, warn, or block",
    )
    justification: str = ""
    rollback_steps: list[str] = Field(default_factory=list)
    risk_of_change: str = Field(
        default="low", description="low, medium, or high",
    )


class RiskAcceptanceRecord(BaseModel):
    """A risk acceptance from dashboard or in-code annotation."""

    resource_address: str
    comment: str = ""
    accepted: bool = False
    expiry_date: str = ""
    approver: str = ""
    source: str = Field(
        default="dashboard",
        description="'dashboard' or 'in_code'",
    )


class ChangeManagementInput(BaseModel):
    inventory: ResourceInventory
    findings: list[Finding] = Field(default_factory=list)
    gap_analyses: list[ComplianceGapAnalysis] = Field(
        default_factory=list,
    )
    business_contexts: list[BusinessContext] = Field(
        default_factory=list,
    )
    risk_acceptances: list[RiskAcceptanceRecord] = Field(
        default_factory=list,
    )
    risk_config: dict[str, Any] = Field(default_factory=dict)


class ChangeManagementOutput(BaseModel):
    change_entries: list[ChangeRiskEntry] = Field(default_factory=list)
    gate_recommendation: str = Field(
        default="pass", description="Overall: pass, warn, or block",
    )
    gate_justification: str = ""
    audit_summary: str = ""


class AuditTrailEntry(BaseModel):
    """Immutable audit record for a change assessment."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = ""
    snapshot_id: str = ""
    commit_sha: str = ""
    repository: str = ""
    changed_resources: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compliance_outcomes: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gate_recommendation: str = "pass"
    gate_justification: str = ""
    agent_version: str = "0.1.0"


class ReportGenerationInput(BaseModel):
    inventory: ResourceInventory = Field(default_factory=ResourceInventory)
    findings: list[Finding] = Field(default_factory=list)
    risk_determinations: list[RiskDetermination] = Field(default_factory=list)
    impact_ratings: list[ImpactRating] = Field(default_factory=list)
    gap_analyses: list[ComplianceGapAnalysis] = Field(default_factory=list)
    quality_score: QualityScore = Field(default_factory=QualityScore)
    output_dir: Path = Path("./reports")
    output_formats: list[str] = Field(default_factory=lambda: ["html", "json"])


class ReportGenerationOutput(BaseModel):
    report_paths: dict[str, str] = Field(
        default_factory=dict, description="Format -> file path"
    )


# ---------------------------------------------------------------------------
# Pipeline-level types
# ---------------------------------------------------------------------------


class PipelineConfig(BaseModel):
    """Configuration for the assessment pipeline."""

    output_dir: Path = Path("./reports")
    output_formats: list[str] = Field(default_factory=lambda: ["html", "json"])
    compliance_frameworks: list[ComplianceFramework] = Field(
        default_factory=lambda: list(ComplianceFramework)
    )
    business_docs_dir: Path | None = None
    cache_dir: Path = Path(".pro-prowler-cache")
    skip_context_analysis: bool = False
    fail_threshold: int = Field(
        default=60,
        description="Quality score below which CI fails",
    )
    agent_timeout_seconds: int = 60
    context_timeout_seconds: int = 120
    repository: str = ""
    linked_repos: list[LinkedRepo] = Field(default_factory=list)
    extra_documents: list[str] = Field(
        default_factory=list,
        description="Pre-built context documents (governance summaries, context sources)",
    )


class AgentResult(BaseModel):
    """Result from a single agent execution."""

    agent_name: str
    status: AgentStatus
    output: Any = None
    duration_ms: int = 0
    error: str | None = None


class PipelineResult(BaseModel):
    """Complete result from the assessment pipeline."""

    agent_results: dict[str, AgentResult] = Field(default_factory=dict)
    quality_score: QualityScore = Field(default_factory=QualityScore)
    total_duration_ms: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_version: str = "0.1.0"
    plan_file_hash: str = ""
