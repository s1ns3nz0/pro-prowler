"""NIST SP 800-30 risk model calculations."""

from __future__ import annotations

from iac_risk.core.enums import RiskLevel, Severity, ThreatSource
from iac_risk.core.schemas import (
    AttackScenario,
    Finding,
    ProwlerCheckDef,
    ResourceChange,
    ThreatEvent,
    Vulnerability,
)

# Fallback templates used when a check has no attack_scenarios defined.
_FALLBACK_TEMPLATES: dict[str, list[ThreatEvent]] = {
    "s3": [
        ThreatEvent(
            threat_source=ThreatSource.ADVERSARIAL,
            event_description=(
                "Unauthorized access to sensitive data in storage"
            ),
            relevance="Cloud storage misconfiguration may expose data",
        ),
    ],
    "security_group": [
        ThreatEvent(
            threat_source=ThreatSource.ADVERSARIAL,
            event_description=(
                "Network-based attack via overly permissive firewall rules"
            ),
            relevance="Open network ports increase attack surface",
        ),
    ],
    "ec2": [
        ThreatEvent(
            threat_source=ThreatSource.ADVERSARIAL,
            event_description=(
                "Compromise of compute instance via exposed services"
            ),
            relevance="Instance misconfiguration enables unauthorized access",
        ),
    ],
    "iam": [
        ThreatEvent(
            threat_source=ThreatSource.ADVERSARIAL,
            event_description=(
                "Privilege escalation through overly permissive IAM policies"
            ),
            relevance="Excessive permissions enable lateral movement",
        ),
    ],
    "rds": [
        ThreatEvent(
            threat_source=ThreatSource.ADVERSARIAL,
            event_description=(
                "Database breach via public accessibility or weak encryption"
            ),
            relevance="Database exposure increases data breach risk",
        ),
    ],
    "general": [
        ThreatEvent(
            threat_source=ThreatSource.ADVERSARIAL,
            event_description=(
                "Undetected malicious activity due to missing monitoring"
            ),
            relevance="Lack of logging delays incident response",
        ),
    ],
}

# Severity -> base likelihood mapping
_SEVERITY_TO_LIKELIHOOD: dict[Severity, RiskLevel] = {
    Severity.CRITICAL: RiskLevel.VERY_HIGH,
    Severity.HIGH: RiskLevel.HIGH,
    Severity.MODERATE: RiskLevel.MODERATE,
    Severity.LOW: RiskLevel.LOW,
    Severity.INFORMATIONAL: RiskLevel.VERY_LOW,
}


def _categorize_resource(resource_type: str) -> str:
    """Map a resource type to a threat category."""
    rt = resource_type.lower()
    if "s3" in rt:
        return "s3"
    if "security_group" in rt:
        return "security_group"
    if "instance" in rt and "rds" not in rt and "db" not in rt:
        return "ec2"
    if "iam" in rt:
        return "iam"
    if "rds" in rt or "db_instance" in rt:
        return "rds"
    return "general"


def _scenario_to_threat_event(
    scenario: AttackScenario,
    finding: Finding,
) -> ThreatEvent:
    """Convert an AttackScenario from check definition to a ThreatEvent."""
    return ThreatEvent(
        threat_source=scenario.threat_source,
        event_description=scenario.description.strip(),
        relevance=scenario.impact.strip(),
        mitre_tactic=scenario.mitre_tactic,
        attack_technique=scenario.technique,
    )


def identify_threat_events(
    finding: Finding,
    check_def: ProwlerCheckDef | None = None,
) -> list[ThreatEvent]:
    """Identify NIST SP 800-30 threat events for a finding.

    If the check definition has attack_scenarios (HackTricks-enriched),
    those are used. Otherwise falls back to generic category templates.
    """
    if check_def and check_def.attack_scenarios:
        return [
            _scenario_to_threat_event(s, finding)
            for s in check_def.attack_scenarios
        ]

    # Fallback to generic category templates
    category = _categorize_resource(
        finding.resource_type or finding.resource_address,
    )
    return list(
        _FALLBACK_TEMPLATES.get(category, _FALLBACK_TEMPLATES["general"])
    )


def identify_vulnerabilities(
    finding: Finding, resource: ResourceChange | None = None,
) -> list[Vulnerability]:
    """Identify vulnerabilities and predisposing conditions."""
    conditions: list[str] = []
    conditions.append(f"Misconfiguration: {finding.description}")

    if finding.actual_value is not None:
        conditions.append(
            f"Current value: {finding.actual_value} "
            f"(expected: {finding.expected_value})"
        )

    if resource and resource.action.value == "create":
        conditions.append(
            "Resource is being newly created with insecure defaults"
        )

    return [
        Vulnerability(
            description=finding.title,
            predisposing_conditions=conditions,
        )
    ]


def determine_likelihood(finding: Finding) -> RiskLevel:
    """Determine likelihood based on finding severity."""
    return _SEVERITY_TO_LIKELIHOOD.get(finding.severity, RiskLevel.MODERATE)


def calculate_risk_level(likelihood: RiskLevel, impact: RiskLevel) -> int:
    """Calculate numeric risk level (1-25) from likelihood × impact."""
    return int(likelihood) * int(impact)


def map_risk_to_severity(risk_level: int) -> Severity:
    """Map a numeric risk level (1-25) to a severity category."""
    if risk_level >= 16:
        return Severity.CRITICAL
    if risk_level >= 9:
        return Severity.HIGH
    if risk_level >= 4:
        return Severity.MODERATE
    if risk_level >= 2:
        return Severity.LOW
    return Severity.INFORMATIONAL
