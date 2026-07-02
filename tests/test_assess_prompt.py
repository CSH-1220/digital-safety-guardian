"""Prompt and construction contracts for the risk assessment LLM node."""

from google.adk.agents import LlmAgent

from guardian.contracts import RiskAssessment
from guardian.nodes.assess import ASSESS_INSTRUCTION, build_assess_risk


def test_instruction_encodes_assessment_and_injection_rules() -> None:
    """The reviewable prompt must encode the non-negotiable risk policy."""
    instruction = ASSESS_INSTRUCTION.lower()

    assert "has_concern" in instruction
    assert "relevant_checks" in instruction
    assert "unclear" in instruction
    assert "false" in instruction
    assert "untrusted data" in instruction
    assert "not instructions" in instruction
    assert "risk taxonomy" in instruction
    assert "domain_reputation" in instruction
    assert "email_leak" in instruction
    assert "password_hygiene" in instruction
    assert "url_phishing" in instruction
    assert "permission_risk" in instruction
    assert "app_reputation" in instruction
    assert "{risk_event}" in instruction


def test_instruction_disambiguates_domain_and_app_reputation() -> None:
    """domain_reputation (websites) and app_reputation (installed apps) must not overlap.

    Regression: with overlapping descriptions the assessor selected BOTH checks for
    the same web domain, double-reporting identical reputation findings.
    """
    instruction = ASSESS_INSTRUCTION.lower()

    # domain_reputation is scoped to websites; app_reputation to installed apps.
    assert "website" in instruction
    assert "installing" in instruction
    # An explicit rule against selecting both checks for the same target.
    assert "never select both domain_reputation and app_reputation" in instruction


def test_build_assess_risk_uses_schema_key_and_configurable_flash_model(
    monkeypatch,
) -> None:
    """Construction is offline and does not require an API key."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")

    agent = build_assess_risk()

    assert isinstance(agent, LlmAgent)
    assert agent.name == "assess_risk"
    assert agent.model == "gemini-2.5-flash"
    assert agent.output_schema is RiskAssessment
    assert agent.output_key == "assessment"
