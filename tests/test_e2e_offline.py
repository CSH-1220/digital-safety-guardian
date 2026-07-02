"""End-to-end test of the real ADK graph via InMemoryRunner — no LLM/credentials.

Uses `build_offline_app` (deterministic assess/advisor stubs, but the REAL
intake, dispatch, routing, and check nodes). Proves the graph executes through
a real runner on a chat `Content` input — i.e. the same path the playground
uses — and produces a valid `GuardianAdvice`.
"""

from google.adk.runners import InMemoryRunner
from google.genai import types

import guardian.offline as offline
from guardian.contracts import GuardianAdvice
from guardian.offline import no_concern_assessment
from guardian.workflow import build_offline_app


def test_graph_runs_end_to_end_on_a_chat_content() -> None:
    app = build_offline_app()
    runner = InMemoryRunner(app=app)
    session = runner.session_service.create_session_sync(user_id="u1", app_name=app.name)

    message = types.Content(
        role="user",
        parts=[
            types.Part.from_text(
                text="I'm about to sign up for phishy-demo.test using leaked@example.com"
            )
        ],
    )

    events = list(
        runner.run(user_id="u1", session_id=session.id, new_message=message)
    )
    assert events, "the graph should emit at least one event"

    session = runner.session_service.get_session_sync(
        user_id="u1", app_name=app.name, session_id=session.id
    )
    advice = GuardianAdvice.model_validate(session.state.get("guardian_advice"))

    assert advice.overall_risk in ("low", "medium", "high")
    # The concern path runs all three deterministic checks.
    assert {finding.check for finding in advice.risks} == {
        "domain_reputation",
        "email_leak",
        "password_hygiene",
    }


def test_no_concern_input_routes_through_default_to_handle_unrelated(monkeypatch) -> None:
    """A benign assessment must reach handle_unrelated via the DEFAULT_ROUTE branch.

    dispatch emits "no_concern", which is no longer an explicit route key: the
    graph relies on DEFAULT_ROUTE as the else-path. This guards that wiring.
    """
    monkeypatch.setattr(offline, "offline_assessment", lambda _event: no_concern_assessment())

    app = build_offline_app()
    runner = InMemoryRunner(app=app)
    session = runner.session_service.create_session_sync(user_id="u1", app_name=app.name)

    message = types.Content(
        role="user",
        parts=[types.Part.from_text(text="what's the weather today?")],
    )
    list(runner.run(user_id="u1", session_id=session.id, new_message=message))

    session = runner.session_service.get_session_sync(
        user_id="u1", app_name=app.name, session_id=session.id
    )
    advice = GuardianAdvice.model_validate(session.state.get("guardian_advice"))

    assert advice.overall_risk == "low"
    assert advice.risks == []
    assert advice.plain_language_summary == "No security concern detected for this action."
