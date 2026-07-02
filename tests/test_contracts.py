import pytest
from pydantic import ValidationError

from guardian.contracts import (
    GuardianAdvice,
    RiskAssessment,
    RiskEvent,
    RiskFinding,
)


def test_risk_event_has_no_password_field() -> None:
    assert "password" not in RiskEvent.model_fields


def test_risk_event_accepts_email_and_domain() -> None:
    event = RiskEvent(
        app_or_domain="xiaohongshu.com",
        email="a@b.com",
        raw_context="signing up",
    )

    assert event.email == "a@b.com"


def test_assessment_roundtrip() -> None:
    assessment = RiskAssessment(
        has_concern=True,
        risk_description="new app, unknown reputation",
        relevant_checks=["domain_reputation", "email_leak", "url_phishing"],
        confidence=0.8,
    )

    assert assessment.relevant_checks == [
        "domain_reputation",
        "email_leak",
        "url_phishing",
    ]


def test_assessment_rejects_unknown_check() -> None:
    with pytest.raises(ValidationError):
        RiskAssessment(
            has_concern=True,
            risk_description="x",
            relevant_checks=["not_a_real_check"],
            confidence=0.5,
        )


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_assessment_rejects_out_of_range_confidence(confidence: float) -> None:
    with pytest.raises(ValidationError):
        RiskAssessment(
            has_concern=True,
            risk_description="x",
            relevant_checks=[],
            confidence=confidence,
        )


def test_guardian_advice_shape() -> None:
    finding = RiskFinding(
        check="email_leak",
        severity="high",
        evidence={"found": True},
        note="email in a leak",
    )
    advice = GuardianAdvice(
        overall_risk="high",
        risks=[finding],
        priority_order=["email_leak"],
        plain_language_summary="fix this",
    )

    assert advice.risks[0].check == "email_leak"


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (RiskEvent, {"password": "not-allowed"}),
        # RiskAssessment intentionally allows extra fields: it is the LLM
        # output_schema and must stay Gemini-structured-output compatible
        # (no additionalProperties). See contracts.RiskAssessment.
        (
            RiskFinding,
            {
                "check": "email_leak",
                "severity": "low",
                "evidence": {},
                "note": "clear",
                "unexpected": "not-allowed",
            },
        ),
        (
            GuardianAdvice,
            {
                "overall_risk": "low",
                "risks": [],
                "priority_order": [],
                "plain_language_summary": "clear",
                "unexpected": "not-allowed",
            },
        ),
    ],
)
def test_contracts_reject_extra_fields(
    model: type[RiskEvent | RiskAssessment | RiskFinding | GuardianAdvice],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)
