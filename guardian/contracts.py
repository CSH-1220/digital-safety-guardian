"""Pydantic contracts for the Digital Safety Guardian engine boundary."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CheckId = Literal[
    "domain_reputation",
    "email_leak",
    "password_hygiene",
    "url_phishing",
    "permission_risk",
    "app_reputation",
]
Severity = Literal["low", "medium", "high", "unknown"]


class _ContractModel(BaseModel):
    """Reject unexpected input at every engine boundary."""

    model_config = ConfigDict(extra="forbid")


class RiskEvent(_ContractModel):
    """A privacy-preserving description of a user action to assess."""

    app_or_domain: str | None = None  # Name of the app or domain involved in the event
    email: str | None = None          # Email address related to the event
    url: str | None = None            # URL associated with the event
    raw_context: str | None = None    # Unstructured or additional context information


class RiskAssessment(BaseModel):
    """Open-ended risk assessment produced by the assessment agent.

    NOTE: plain BaseModel (no ``extra="forbid"``) on purpose. This model is the
    LLM ``output_schema`` for ``assess_risk``; ADK passes it to Gemini as the
    structured-output ``response_schema``, and Gemini rejects the
    ``additionalProperties`` that ``extra="forbid"`` would emit.
    """

    has_concern: bool                       # True if potential risk is detected
    risk_description: str                   # Human-readable description of the risk
    relevant_checks: list[CheckId]          # List of check IDs relevant for the assessment
    confidence: float = Field(ge=0, le=1)   # Confidence score for the risk assessment (0-1)
    extracted_domain: str | None = None     # Bare domain pulled from free-text input (no URL)
    extracted_email: str | None = None      # Email pulled from free-text input (never a password)


class RiskFinding(_ContractModel):
    """Result from one deterministic safety check."""

    check: CheckId              # ID of the safety check performed
    severity: Severity          # Severity level of the finding
    evidence: dict              # Details or evidence supporting the finding
    note: str                   # Additional commentary or context about the finding


class GuardianAdvice(_ContractModel):
    """Prioritized, plain-language guidance returned to the caller."""

    overall_risk: Literal["low", "medium", "high"]  # Overall assessed risk level
    risks: list[RiskFinding]                        # List of individual risk findings
    priority_order: list[CheckId]                   # List of check IDs in recommended priority
    plain_language_summary: str                     # Human-readable summary of advice


class GuardianAdviceDraft(BaseModel):
    """Gemini-compatible advisor draft before deterministic normalization.

    ``GuardianAdvice`` remains the strict final engine contract, but it cannot
    be sent directly as a Gemini structured-output schema because it contains
    nested strict models and open ``dict`` evidence fields. The advisor emits
    this flat draft; a deterministic node then combines it with the original
    tool findings to create a validated ``GuardianAdvice``.
    """

    overall_risk: Literal["low", "medium", "high"]
    priority_order: list[CheckId]
    plain_language_summary: str
