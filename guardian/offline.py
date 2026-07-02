"""Credential-free deterministic nodes for the offline graph and unit tests.

``build_offline_app`` wires ``offline_assess_risk`` and ``offline_advisor`` into
the real graph so tests can exercise routing, checks, and finalization without
Gemini credentials (see ``tests/test_e2e_offline.py``).
"""

from google.adk.agents.context import Context
from google.adk.events import Event

from guardian.contracts import GuardianAdvice, RiskAssessment, RiskEvent, RiskFinding
from guardian.state_keys import ASSESSMENT, GUARDIAN_ADVICE, RISK_EVENT

_ADVICE_KEY = GUARDIAN_ADVICE
_ASSESSMENT_KEY = ASSESSMENT
_EVENT_KEY = RISK_EVENT


def advice_for_event(event: RiskEvent) -> GuardianAdvice:
    """Return deterministic advice without calling external services or an LLM."""
    del event
    findings = _offline_findings()
    return GuardianAdvice(
        overall_risk="medium",
        risks=findings,
        priority_order=["domain_reputation", "email_leak", "password_hygiene"],
        plain_language_summary=(
            "Review the service before sharing personal data, check whether "
            "the email has appeared in synthetic breach data, and use a "
            "unique password in your password manager."
        ),
    )


def offline_assessment(event: RiskEvent) -> RiskAssessment:
    """Provide a stable concern fixture for the explicit offline workflow."""
    del event
    return RiskAssessment(
        has_concern=True,
        risk_description="A new service may require basic safety checks.",
        relevant_checks=["domain_reputation", "email_leak", "password_hygiene"],
        confidence=1.0,
    )


def no_concern_assessment() -> RiskAssessment:
    """Return an explicit fixture for deterministic no-concern routing tests."""
    return RiskAssessment(
        has_concern=False,
        risk_description="No security-relevant action was identified.",
        relevant_checks=[],
        confidence=1.0,
    )


def offline_assess_risk(ctx: Context) -> Event:
    """Write a deterministic assessment when exercising the offline graph."""
    event = RiskEvent.model_validate(ctx.state.get(_EVENT_KEY, {}))
    assessment_data = offline_assessment(event).model_dump()
    ctx.state[_ASSESSMENT_KEY] = assessment_data
    return Event(state={_ASSESSMENT_KEY: assessment_data})


def offline_advisor(ctx: Context) -> Event:
    """Write deterministic terminal advice for the offline graph."""
    event = RiskEvent.model_validate(ctx.state.get(_EVENT_KEY, {}))
    advice_data = advice_for_event(event).model_dump()
    ctx.state[_ADVICE_KEY] = advice_data
    return Event(output=advice_data, state={_ADVICE_KEY: advice_data})


def _offline_findings() -> list[RiskFinding]:
    return [
        RiskFinding(
            check="domain_reputation",
            severity="unknown",
            evidence={"source": "offline"},
            note="Domain reputation is not checked in the offline harness.",
        ),
        RiskFinding(
            check="email_leak",
            severity="unknown",
            evidence={"source": "offline"},
            note="Email leak status is not checked in the offline harness.",
        ),
        RiskFinding(
            check="password_hygiene",
            severity="low",
            evidence={"source": "offline"},
            note="Use a unique password stored in a password manager.",
        ),
    ]
