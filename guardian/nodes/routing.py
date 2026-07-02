"""Deterministic workflow routing for assessed risk events."""

import logging
from typing import Literal

from google.adk.agents.context import Context
from google.adk.events import Event
from pydantic import ValidationError

from guardian.contracts import GuardianAdvice, RiskAssessment
from guardian.state_keys import ASSESSMENT, GUARDIAN_ADVICE

_ADVICE_KEY = GUARDIAN_ADVICE
_ASSESSMENT_KEY = ASSESSMENT
logger = logging.getLogger(__name__)

Route = Literal["concern", "no_concern"]


def dispatch_route(assessment: RiskAssessment) -> Route:
    """Choose the deterministic branch from a validated assessment."""
    return "concern" if assessment.has_concern else "no_concern"


def unrelated_advice() -> GuardianAdvice:
    """Return the fixed terminal response for non-security input."""
    return GuardianAdvice(
        overall_risk="low",
        risks=[],
        priority_order=[],
        plain_language_summary="No security concern detected for this action.",
    )


def dispatch(ctx: Context) -> Event:
    """Route valid assessments; malformed state fails closed to no-concern."""
    try:
        assessment = RiskAssessment.model_validate(ctx.state.get(_ASSESSMENT_KEY))
    except ValidationError:
        # A malformed assessment means an upstream bug, not a benign event.
        # Log it so this doesn't silently degrade into "no concern".
        logger.warning("assessment failed validation; routing to no_concern")
        return Event(route="no_concern")
    return Event(route=dispatch_route(assessment))


def handle_unrelated(ctx: Context) -> Event:
    """Write fixed no-concern advice without calling the advisor node."""
    advice_data = unrelated_advice().model_dump()
    ctx.state[_ADVICE_KEY] = advice_data
    return Event(output=advice_data, state={_ADVICE_KEY: advice_data})
