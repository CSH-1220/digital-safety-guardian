"""Unit tests for the intake node's input normalization."""

from google.genai import types

from guardian.contracts import RiskEvent
from guardian.nodes.intake import _to_risk_event


def _chat_content(text: str) -> types.Content:
    """Build the genai Content the playground / adk web sends for a chat turn."""
    return types.Content(role="user", parts=[types.Part.from_text(text=text)])


def test_pasted_json_object_becomes_a_structured_risk_event() -> None:
    """A JSON object pasted into the chat box must populate structured fields.

    The playground delivers chat input as text, not a dict, so intake has to
    recognize a JSON payload itself. This is the path a live demo relies on.
    """
    payload = (
        '{"app_or_domain": "phishy-demo.test", "email": "leaked@example.com", '
        '"url": "https://phishy-demo.test/signup", '
        '"raw_context": "User is creating a new account."}'
    )

    event = _to_risk_event(_chat_content(payload))

    assert event.app_or_domain == "phishy-demo.test"
    assert event.email == "leaked@example.com"
    assert event.url == "https://phishy-demo.test/signup"
    assert event.raw_context == "User is creating a new account."


def test_natural_language_text_still_goes_to_raw_context() -> None:
    """Non-JSON chat input keeps the original free-text behavior."""
    event = _to_risk_event(_chat_content("Is it safe to sign up for this site?"))

    assert event.app_or_domain is None
    assert event.url is None
    assert event.raw_context == "Is it safe to sign up for this site?"


def test_plain_dict_input_is_validated_directly() -> None:
    """A real dict (non-chat caller) is still validated as a RiskEvent."""
    event = _to_risk_event(
        {"app_or_domain": "example.com", "url": "https://example.com/login"}
    )

    assert event.app_or_domain == "example.com"
    assert event.url == "https://example.com/login"


def test_json_with_unknown_fields_falls_back_to_raw_context() -> None:
    """RiskEvent forbids extra keys, so malformed JSON is treated as free text."""
    payload = '{"app_or_domain": "example.com", "password": "hunter2"}'

    event = _to_risk_event(_chat_content(payload))

    # The payload is preserved as text (never parsed into a password field).
    assert event.app_or_domain is None
    assert event.raw_context == payload
    assert isinstance(event, RiskEvent)
