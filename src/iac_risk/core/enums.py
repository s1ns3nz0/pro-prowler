"""Core enumerations used across the IaC risk assessment pipeline."""

from enum import Enum, IntEnum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RiskLevel(IntEnum):
    VERY_LOW = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    VERY_HIGH = 5


class ComplianceFramework(str, Enum):
    PCI_DSS = "PCI_DSS"
    ISO_27001 = "ISO_27001"
    ISO_27701 = "ISO_27701"
    SOC_2 = "SOC_2"
    GDPR = "GDPR"
    ISMS_P = "ISMS_P"


class GateRecommendation(str, Enum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


class ThreatSource(str, Enum):
    ADVERSARIAL = "ADVERSARIAL"
    ACCIDENTAL = "ACCIDENTAL"
    STRUCTURAL = "STRUCTURAL"
    ENVIRONMENTAL = "ENVIRONMENTAL"


class ResourceAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    NO_OP = "no-op"
    READ = "read"


class AgentStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class LetterGrade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class ControlStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNMAPPED = "UNMAPPED"


class DetectionOperator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX_MATCH = "regex_match"
    LESS_THAN = "less_than"
    GREATER_THAN = "greater_than"
