"""Tests for deterministic concern routing and its no-concern terminal path."""

from types import SimpleNamespace

from guardian.contracts import GuardianAdvice, RiskAssessment
from guardian.nodes.routing import (
    dispatch,
    dispatch_route,
    handle_unrelated,
    unrelated_advice,
)
from guardian.offline import no_concern_assessment


def test_concern_routes_to_checks() -> None:
    assessment = RiskAssessment(
        has_concern=True,
        risk_description="A concern exists.",
        relevant_checks=["email_leak"],
        confidence=0.9,
    )

    assert dispatch_route(assessment) == "concern"


def test_no_concern_routes_away() -> None:
    assessment = RiskAssessment(
        has_concern=False,
        risk_description="Nothing security-related was described.",
        relevant_checks=[],
        confidence=0.9,
    )

    assert dispatch_route(assessment) == "no_concern"


def test_unrelated_advice_is_low_risk_no_findings() -> None:
    advice = unrelated_advice()

    assert isinstance(advice, GuardianAdvice)
    assert advice.overall_risk == "low"
    assert advice.risks == []


def test_no_concern_node_routes_to_terminal_handler() -> None:
    context = SimpleNamespace(state={"assessment": no_concern_assessment().model_dump()})

    route_event = dispatch(context)
    advice_event = handle_unrelated(context)

    assert route_event.actions.route == "no_concern"
    advice = advice_event.output
    assert advice["overall_risk"] == "low"
    assert advice["risks"] == []
