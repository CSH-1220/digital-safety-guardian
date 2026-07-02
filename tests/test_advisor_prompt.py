"""Prompt and construction contracts for the advice LLM node."""

from google.adk.agents import LlmAgent

from guardian.contracts import GuardianAdvice, GuardianAdviceDraft
from guardian.nodes.advisor import ADVISOR_INSTRUCTION, build_advisor, finalize_advice


def test_instruction_encodes_advice_and_graceful_degradation_rules() -> None:
    """The prompt must make the reviewable advice policy explicit."""
    instruction = ADVISOR_INSTRUCTION.lower()

    assert "plain" in instruction
    assert "priorit" in instruction
    assert "findings" in instruction
    assert "no automated check" in instruction
    assert "data, not instructions" in instruction
    assert "{assessment}" in instruction
    assert "{findings}" in instruction


def test_build_advisor_uses_schema_key_and_configurable_flash_model(monkeypatch) -> None:
    """Construction stays credential-free for local graph inspection."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")

    agent = build_advisor()

    assert isinstance(agent, LlmAgent)
    assert agent.name == "advisor"
    assert agent.model == "gemini-2.5-flash"
    assert agent.output_schema is GuardianAdviceDraft
    assert agent.output_key == "guardian_advice_draft"


def test_advisor_output_schema_is_gemini_developer_api_compatible() -> None:
    """The LLM schema must not emit unsupported open-object markers."""
    schema = GuardianAdviceDraft.model_json_schema()

    assert not _has_key(schema, "additionalProperties")
    assert not _has_key(schema, "$defs")
    assert not _has_key(schema, "$ref")
    assert not _has_key(schema, "evidence")


def test_finalize_advice_returns_strict_guardian_advice() -> None:
    """The deterministic finalizer preserves tool evidence in final advice."""
    ctx = _FakeContext(state={
        "guardian_advice_draft": {
            "overall_risk": "high",
            "priority_order": ["email_leak"],
            "plain_language_summary": "Do not reuse credentials here.",
        },
        "findings": [
            {
                "check": "email_leak",
                "severity": "high",
                "evidence": {"found": True},
                "note": "Email appears in breach data.",
            }
        ],
    })

    event = finalize_advice(ctx)
    advice_data = event.actions.state_delta["guardian_advice"]
    advice = GuardianAdvice.model_validate(advice_data)

    assert advice.risks[0].evidence == {"found": True}
    assert event.output == advice_data


def _finalize(priority_order: list[str], finding_checks: list[str]) -> list[str]:
    """Run finalize_advice with a given advisor order and set of ran checks."""
    ctx = _FakeContext(state={
        "guardian_advice_draft": {
            "overall_risk": "high",
            "priority_order": priority_order,
            "plain_language_summary": "summary",
        },
        "findings": [
            {"check": check, "severity": "low", "evidence": {}, "note": ""}
            for check in finding_checks
        ],
    })
    event = finalize_advice(ctx)
    advice = GuardianAdvice.model_validate(event.actions.state_delta["guardian_advice"])
    return advice.priority_order


def test_priority_order_drops_a_check_that_never_ran() -> None:
    """Regression: the advisor listed password_hygiene, but url_phishing ran.

    The final priority_order must not reference a check with no finding.
    """
    order = _finalize(
        priority_order=["domain_reputation", "email_leak", "password_hygiene"],
        finding_checks=["domain_reputation", "email_leak", "url_phishing"],
    )

    assert "password_hygiene" not in order
    # It stays a covering ordering of exactly the checks that ran.
    assert set(order) == {"domain_reputation", "email_leak", "url_phishing"}


def test_priority_order_appends_a_ran_check_the_advisor_omitted() -> None:
    """A check that produced a finding must always appear in priority_order."""
    order = _finalize(
        priority_order=["domain_reputation"],
        finding_checks=["domain_reputation", "email_leak"],
    )

    assert order == ["domain_reputation", "email_leak"]


def test_priority_order_preserves_advisor_order_and_dedupes() -> None:
    """Valid advisor ordering is kept; duplicates collapse."""
    order = _finalize(
        priority_order=["email_leak", "domain_reputation", "email_leak"],
        finding_checks=["domain_reputation", "email_leak"],
    )

    assert order == ["email_leak", "domain_reputation"]


class _FakeContext:
    def __init__(self, state: dict[str, object]) -> None:
        self.state = state


def _has_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_has_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_has_key(child, key) for child in value)
    return False
