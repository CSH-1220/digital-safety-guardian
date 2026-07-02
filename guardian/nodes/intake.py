"""Validated input intake node for the production workflow.

The first node receives whatever the caller sends. Via `adk web` /
`agents-cli playground` that is a `google.genai` ``Content`` (a chat message),
not a structured ``RiskEvent``. We therefore accept ``Any`` (so ADK does not
try to validate the message against ``RiskEvent``) and normalize it into a
``RiskEvent`` ourselves: free text goes into ``raw_context``; the LLM assessor
extracts the domain/email downstream.
"""

import json
import logging
from typing import Any

from google.adk.agents.context import Context
from google.adk.events import Event
from pydantic import ValidationError

from guardian.contracts import RiskEvent
from guardian.state_keys import FINDINGS, RISK_EVENT

_EVENT_KEY = RISK_EVENT
_FINDINGS_KEY = FINDINGS
logger = logging.getLogger(__name__)


def _extract_text(node_input: Any) -> str:
    """Pull text out of a genai Content (or fall back to str)."""
    parts = getattr(node_input, "parts", None)
    if parts:
        texts = [getattr(part, "text", None) for part in parts]
        return " ".join(text for text in texts if text).strip()
    return str(node_input).strip() if node_input is not None else ""


def _risk_event_from_json_text(text: str) -> RiskEvent | None:
    """Parse a pasted JSON object into a RiskEvent, or None if it isn't one.

    The playground / adk web delivers chat input as text, so a structured demo
    payload arrives as a JSON string rather than a dict. Only strict RiskEvent
    objects are accepted (extra keys are forbidden); anything else falls back to
    free text so a password can never be smuggled into a structured field.
    """
    stripped = text.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        return RiskEvent.model_validate(data)
    except ValidationError:
        return None


def _to_risk_event(node_input: Any) -> RiskEvent:
    """Normalize any supported input into a RiskEvent (no password, ever)."""
    if isinstance(node_input, RiskEvent):
        return node_input
    if isinstance(node_input, dict):
        try:
            return RiskEvent.model_validate(node_input)
        except ValidationError:
            # Not a well-formed RiskEvent dict; fall through to text handling.
            logger.debug("dict input did not validate as RiskEvent; treating as text")
    text = _extract_text(node_input)
    structured = _risk_event_from_json_text(text)
    if structured is not None:
        return structured
    return RiskEvent(raw_context=text or None)


def intake(ctx: Context, node_input: Any) -> Event:
    """Store the event and initialize findings for downstream prompt templates."""
    event_data = _to_risk_event(node_input).model_dump()
    ctx.state[_EVENT_KEY] = event_data
    ctx.state[_FINDINGS_KEY] = []
    return Event(state={_EVENT_KEY: event_data, _FINDINGS_KEY: []})
