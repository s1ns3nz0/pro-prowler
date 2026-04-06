"""Typed exceptions for the IaC risk assessment pipeline."""


class IaCRiskError(Exception):
    """Base exception for all IaC risk assessment errors."""


class SchemaValidationError(IaCRiskError):
    """Raised when input data fails schema validation."""


class AgentError(IaCRiskError):
    """Raised when an agent encounters an unrecoverable error."""

    def __init__(self, agent_name: str, message: str) -> None:
        self.agent_name = agent_name
        super().__init__(f"Agent '{agent_name}' failed: {message}")


class PipelineError(IaCRiskError):
    """Raised when the pipeline encounters a critical failure."""


class UnsupportedFormatError(IaCRiskError):
    """Raised when an unsupported Terraform plan format is encountered."""


class CheckEvaluationError(IaCRiskError):
    """Raised when a Prowler check cannot be evaluated."""
