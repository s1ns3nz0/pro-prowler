"""Risk Analysis Agent — NIST SP 800-30 risk determination + AI attack paths."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from iac_risk.agents.base import BaseAgent, ValidationResult
from iac_risk.core.enums import ThreatSource
from iac_risk.core.schemas import (
    AttackPath,
    BusinessContext,
    Finding,
    ResourceChange,
    RiskAnalysisInput,
    RiskAnalysisOutput,
    RiskDetermination,
    ThreatActor,
)
from iac_risk.services.content_hash import hash_string
from iac_risk.services.nist_risk_model import (
    determine_likelihood,
    identify_threat_events,
    identify_vulnerabilities,
)
from iac_risk.services.prowler_catalog import ProwlerCatalog

logger = logging.getLogger(__name__)

_SERVICE_CATEGORY_MAP: dict[str, str] = {
    "s3": "S3",
    "db_instance": "RDS",
    "db_subnet": "RDS",
    "rds": "RDS",
    "instance": "EC2",
    "launch_template": "EC2",
    "security_group": "EC2",
    "vpc": "VPC",
    "subnet": "VPC",
    "route_table": "VPC",
    "internet_gateway": "VPC",
    "nat_gateway": "VPC",
    "eip": "VPC",
    "flow_log": "VPC",
    "ecs": "ECS",
    "ecr": "ECS",
    "iam": "IAM",
    "kms": "KMS",
    "lambda": "Lambda",
    "cloudtrail": "CloudTrail",
    "cloudwatch": "CloudWatch",
    "cloudfront": "CloudFront",
    "lb": "ELB",
    "alb": "ELB",
    "elb": "ELB",
    "target_group": "ELB",
    "listener": "ELB",
    "dynamodb": "DynamoDB",
    "sqs": "SQS",
    "sns": "SNS",
    "secretsmanager": "Secrets",
    "acm": "ACM",
    "elasticache": "ElastiCache",
    "api_gateway": "APIGateway",
    "apigateway": "APIGateway",
    "guardduty": "GuardDuty",
    "securityhub": "SecurityHub",
    "config": "Config",
    "ebs": "EBS",
}


def categorize_service(resource_type: str) -> str:
    """Map a Terraform resource type to an AWS service category."""
    rt = resource_type.lower().replace("aws_", "")
    for key, category in _SERVICE_CATEGORY_MAP.items():
        if key in rt:
            return category
    return "Other"


def _compute_fingerprint(
    address: str,
    resource_type: str,
    check_ids: list[str],
    config: dict[str, Any] | None,
) -> str:
    """Compute a stable fingerprint for attack path caching."""
    data = json.dumps(
        {
            "address": address,
            "type": resource_type,
            "checks": sorted(check_ids),
            "config": config or {},
        },
        sort_keys=True,
    )
    return hash_string(data)


def _load_attack_path_cache(cache_dir: Path) -> dict[str, AttackPath]:
    """Load cached attack paths from disk."""
    cache_file = cache_dir / "attack_paths_cache.json"
    if not cache_file.exists():
        return {}
    try:
        with open(cache_file) as f:
            data = json.load(f)
        return {
            k: AttackPath.model_validate(v)
            for k, v in data.items()
        }
    except (json.JSONDecodeError, OSError):
        return {}


def _save_attack_path_cache(
    cache_dir: Path, cache: dict[str, AttackPath],
) -> None:
    """Save attack paths cache to disk."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "attack_paths_cache.json"
    data = {k: v.model_dump() for k, v in cache.items()}
    with open(cache_file, "w") as f:
        json.dump(data, f, indent=2)


_STANDARD_ACTORS = [
    "External Attacker",
    "Malicious Insider",
    "Compromised Credentials",
    "Accidental User",
    "Supply Chain Attacker",
]


def _aggregate_threat_actors_from_findings(
    findings: list[Finding],
) -> list[ThreatActor]:
    """Aggregate threat actors from findings, deduplicating by actor_name."""
    by_name: dict[str, ThreatActor] = {}
    for f in findings:
        for actor in f.threat_actors:
            existing = by_name.get(actor.actor_name)
            if existing is None:
                by_name[actor.actor_name] = ThreatActor(
                    actor_name=actor.actor_name,
                    actor_type=actor.actor_type,
                    capability=actor.capability,
                    motivation=actor.motivation,
                    techniques=list(actor.techniques),
                    mitre_tactics=list(actor.mitre_tactics),
                    impact=actor.impact,
                )
            else:
                for tech in actor.techniques:
                    if tech not in existing.techniques:
                        existing.techniques.append(tech)
                for tac in actor.mitre_tactics:
                    if tac not in existing.mitre_tactics:
                        existing.mitre_tactics.append(tac)
    return list(by_name.values())


def _extract_json_from_text(text: str) -> Any:
    """Robust JSON extraction handling markdown and preamble."""
    text = text.strip()
    if "```" in text:
        parts = text.split("```")
        for part in parts[1::2]:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("[") or part.startswith("{"):
                text = part
                break
    if not text.startswith("[") and not text.startswith("{"):
        start_obj = text.find("{")
        start_arr = text.find("[")
        if start_obj == -1:
            start = start_arr
        elif start_arr == -1:
            start = start_obj
        else:
            start = min(start_obj, start_arr)
        if start != -1:
            text = text[start:]
    return json.loads(text)


def _generate_attack_path_via_llm(
    resource: ResourceChange,
    findings: list[Finding],
    business_context: BusinessContext | None,
    service_category: str,
) -> tuple[str, str, list[ThreatActor]]:
    """Call LLM to generate attack narrative and structured threat actors.

    Returns (attack_narrative, risk_summary, threat_actors).
    Falls back to deterministic generation if LLM unavailable.
    """
    from iac_risk.services.llm_client import call_llm

    finding_descriptions = "\n".join(
        f"- {f.title} ({f.severity.value}): {f.description}"
        for f in findings
    )

    # Collect existing actors from finding-level definitions
    known_actors = _aggregate_threat_actors_from_findings(findings)
    known_actor_text = "\n".join(
        f"- {a.actor_name} ({a.capability}): "
        f"{', '.join(a.techniques[:3])}"
        for a in known_actors
    ) if known_actors else "None"

    context_text = ""
    if business_context:
        context_text = (
            f"\nBusiness context: "
            f"{business_context.data_classification} data, "
            f"criticality {business_context.asset_criticality.name}"
        )

    system = (
        "You are a cloud security analyst. Given AWS resource findings, "
        "produce a chained attack narrative and identify which threat "
        "actors (from the standard list) would target this resource. "
        f"Standard actors: {', '.join(_STANDARD_ACTORS)}. "
        "Respond ONLY with valid JSON matching this schema:\n"
        "{\n"
        '  "narrative": "3-5 sentence chained attack description",\n'
        '  "summary": "one-line risk summary",\n'
        '  "threat_actors": [\n'
        "    {\n"
        '      "actor_name": "External Attacker",\n'
        '      "capability": "Low|Medium|High|Nation-state",\n'
        '      "motivation": "why they would attack this",\n'
        '      "techniques": ["technique 1", "technique 2"],\n'
        '      "mitre_tactics": ["TA0001", "TA0009"],\n'
        '      "impact": "business impact if successful"\n'
        "    }\n"
        "  ]\n"
        "}"
    )
    user_msg = (
        f"AWS {service_category} resource: "
        f"{resource.address} ({resource.resource_type})\n"
        f"Config: {json.dumps(resource.after_config or {})[:600]}\n"
        f"Findings:\n{finding_descriptions}\n"
        f"Known threat actors from check definitions:\n{known_actor_text}\n"
        f"{context_text}\n\n"
        f"Identify 2-4 threat actors from the standard list that would "
        f"realistically target this resource. Combine techniques from "
        f"all findings into each actor's techniques list."
    )

    text = call_llm(system, user_msg, max_tokens=2048)
    if not text:
        return _generate_attack_path_deterministic(
            resource, findings, service_category,
        )

    try:
        data = _extract_json_from_text(text)
        narrative = data.get("narrative", "")
        summary = data.get("summary", "")
        actors: list[ThreatActor] = []
        for a in data.get("threat_actors", []):
            try:
                # Default actor_type based on name
                actor_type = ThreatSource.ADVERSARIAL
                if a.get("actor_name") == "Accidental User":
                    actor_type = ThreatSource.ACCIDENTAL
                actors.append(ThreatActor(
                    actor_name=a.get("actor_name", "External Attacker"),
                    actor_type=actor_type,
                    capability=a.get("capability", "Medium"),
                    motivation=a.get("motivation", ""),
                    techniques=a.get("techniques", []),
                    mitre_tactics=a.get("mitre_tactics", []),
                    impact=a.get("impact", ""),
                ))
            except Exception as e:
                logger.warning("Threat actor parse failed: %s", e)
        if not actors:
            actors = known_actors
        return narrative, summary, actors
    except Exception as e:
        logger.warning("Attack path LLM response parse failed: %s", e)
        return _generate_attack_path_deterministic(
            resource, findings, service_category,
        )


def _generate_attack_path_deterministic(
    resource: ResourceChange,
    findings: list[Finding],
    service_category: str,
) -> tuple[str, str, list[ThreatActor]]:
    """Generate a deterministic attack path from findings (no LLM)."""
    steps = []
    for f in findings:
        if f.threat_actors and f.threat_actors[0].techniques:
            steps.append(f.threat_actors[0].techniques[0])
        elif f.attack_scenarios:
            steps.append(f.attack_scenarios[0].technique)
        else:
            steps.append(f.title)

    chain = " → ".join(steps)
    narrative = (
        f"Resource {resource.address} ({service_category}) has "
        f"{len(findings)} misconfiguration(s). "
        f"Attack chain: {chain}. "
        f"Combined, these create a {findings[0].severity.value}-severity "
        f"attack surface requiring immediate remediation."
    )
    summary = (
        f"{len(findings)} findings on {service_category} resource "
        f"enabling {steps[0] if steps else 'unknown attack'}"
    )
    actors = _aggregate_threat_actors_from_findings(findings)
    return narrative, summary, actors


class RiskAnalysisAgent(BaseAgent):
    name = "risk_analysis"
    critical = True

    def __init__(
        self,
        catalog: ProwlerCatalog | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        self.catalog = catalog or ProwlerCatalog()
        self.cache_dir = cache_dir or Path(".pro-prowler-cache")

    def validate_input(self, input_data: Any) -> ValidationResult:
        if not isinstance(input_data, RiskAnalysisInput):
            return ValidationResult(
                valid=False, error="Expected RiskAnalysisInput",
            )
        return ValidationResult(valid=True)

    def assess(self, input_data: RiskAnalysisInput) -> RiskAnalysisOutput:
        inventory = input_data.inventory
        findings = input_data.findings
        business_contexts = input_data.business_contexts
        determinations: list[RiskDetermination] = []

        resource_map = {r.address: r for r in inventory.resources}

        # NIST SP 800-30 risk determinations
        for finding in findings:
            check_def = self.catalog.get_check_by_id(finding.check_id)
            threat_events = identify_threat_events(finding, check_def)
            resource = resource_map.get(finding.resource_address)
            vulnerabilities = identify_vulnerabilities(finding, resource)
            likelihood = determine_likelihood(finding)

            determination = RiskDetermination(
                finding_id=finding.finding_id,
                threat_events=threat_events,
                vulnerabilities=vulnerabilities,
                likelihood=likelihood,
                risk_level=0,
                risk_severity=finding.severity,
            )
            determinations.append(determination)

        # AI attack paths per resource
        attack_paths = self._generate_attack_paths(
            findings, resource_map, business_contexts,
        )

        logger.info(
            "Risk analysis complete: %d determinations, %d attack paths",
            len(determinations),
            len(attack_paths),
        )

        return RiskAnalysisOutput(
            risk_determinations=determinations,
            attack_paths=attack_paths,
        )

    def _generate_attack_paths(
        self,
        findings: list[Finding],
        resource_map: dict[str, ResourceChange],
        business_contexts: list[BusinessContext],
    ) -> list[AttackPath]:
        """Generate per-resource attack paths with fingerprint caching."""
        import fnmatch

        # Group findings by resource
        by_resource: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            by_resource[f.resource_address].append(f)

        # Load cache
        cache = _load_attack_path_cache(self.cache_dir)
        paths: list[AttackPath] = []
        cache_updated = False

        for address, resource_findings in by_resource.items():
            resource = resource_map.get(address)
            if not resource:
                continue

            service = categorize_service(resource.resource_type)
            check_ids = [f.check_id for f in resource_findings]
            fp = _compute_fingerprint(
                address,
                resource.resource_type,
                check_ids,
                resource.after_config,
            )

            # Check cache
            if fp in cache:
                paths.append(cache[fp])
                continue

            # Find business context for this resource
            ctx = None
            for bc in business_contexts:
                pattern = bc.resource_pattern
                if (
                    fnmatch.fnmatch(address, pattern)
                    or fnmatch.fnmatch(address, f"*{pattern}")
                ):
                    ctx = bc
                    break

            # Generate attack path with structured threat actors
            narrative, summary, threat_actors = _generate_attack_path_via_llm(
                resource, resource_findings, ctx, service,
            )

            path = AttackPath(
                resource_address=address,
                resource_type=resource.resource_type,
                service_category=service,
                finding_ids=[f.finding_id for f in resource_findings],
                attack_narrative=narrative,
                threat_actors=threat_actors,
                risk_summary=summary,
                fingerprint=fp,
            )
            paths.append(path)
            cache[fp] = path
            cache_updated = True

        if cache_updated:
            _save_attack_path_cache(self.cache_dir, cache)

        return paths
