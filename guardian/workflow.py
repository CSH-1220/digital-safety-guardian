"""Production and credential-free ADK workflow wiring."""

# Verified against installed google-adk source (2026-06-26): App is imported
# from google.adk.apps.app; Workflow, Edge, START, and @node live in
# google.adk.workflow; Context is google.adk.agents.context.Context; Event is
# google.adk.events.Event; and InMemoryRunner is google.adk.runners.InMemoryRunner.
# This version has no Edge.chain: Workflow accepts tuple chains and route maps.

from typing import Any

from google.adk.apps.app import App
from google.adk.workflow import DEFAULT_ROUTE, START, JoinNode, Workflow, node

from guardian.nodes.advisor import build_advisor, finalize_advice
from guardian.nodes.assess import build_assess_risk
from guardian.nodes.checks import (
    app_reputation_check,
    collect_findings,
    leak_check,
    password_tips,
    permission_risk_check,
    reputation_check,
    url_phishing_check,
)
from guardian.nodes.intake import intake
from guardian.nodes.routing import dispatch, handle_unrelated
from guardian.offline import offline_advisor, offline_assess_risk


def _build_check_stage() -> tuple[tuple[Any, ...], JoinNode, Any]:
    """Build the parallel safety-check stage shared by both graphs.

    Returns the fan-out ``check_nodes`` tuple, the ``JoinNode`` that
    re-converges them, and the ``collect_findings`` fan-in node. Each call
    creates fresh node instances so the two graphs never share state.
    """
    check_nodes = (
        node(reputation_check),
        node(leak_check),
        node(password_tips),
        node(url_phishing_check),
        node(permission_risk_check),
        node(app_reputation_check),
    )
    checks_join_node = JoinNode(name="checks_complete")
    collect_node = node(collect_findings)
    return check_nodes, checks_join_node, collect_node


def build_app() -> App:
    """Build the production graph with its two schema-constrained LLM nodes."""
    intake_node = node(intake)
    assessment_node = build_assess_risk()
    dispatch_node = node(dispatch)
    check_nodes, checks_join_node, collect_node = _build_check_stage()
    advisor_node = build_advisor()
    finalizer_node = node(finalize_advice)
    unrelated_node = node(handle_unrelated)
    workflow = Workflow(
        name="guardian",
        edges=[
            (
                START,
                intake_node,
                assessment_node,
                dispatch_node,
                {
                    # "concern" fans out to the parallel checks; every other
                    # route (dispatch emits "no_concern", and malformed state
                    # fails closed to "no_concern") falls through to the default
                    # branch. Using DEFAULT_ROUTE as the else-path declares an
                    # explicit default and silences the graph's "[NO DEFAULT]"
                    # warning.
                    "concern": check_nodes,
                    DEFAULT_ROUTE: unrelated_node,
                },
            ),
            (
                check_nodes,
                checks_join_node,
                collect_node,
                advisor_node,
                finalizer_node,
            ),
        ],
    )
    # App name MUST match the agent directory ("guardian") so adk web /
    # agents-cli playground sessions resolve correctly.
    return App(name="guardian", root_agent=workflow)


def build_offline_app() -> App:
    """Build a deterministic graph for tests that cannot use Gemini credentials."""
    intake_node = node(intake)
    assessment_node = node(offline_assess_risk, name="assess_risk_offline")
    dispatch_node = node(dispatch)
    check_nodes, checks_join_node, collect_node = _build_check_stage()
    advisor_node = node(offline_advisor, name="advisor_offline")
    unrelated_node = node(handle_unrelated)
    workflow = Workflow(
        name="guardian_offline",
        edges=[
            (
                START,
                intake_node,
                assessment_node,
                dispatch_node,
                {
                    # "concern" fans out to the parallel checks; every other
                    # route (dispatch emits "no_concern", and malformed state
                    # fails closed to "no_concern") falls through to the default
                    # branch. Using DEFAULT_ROUTE as the else-path declares an
                    # explicit default and silences the graph's "[NO DEFAULT]"
                    # warning.
                    "concern": check_nodes,
                    DEFAULT_ROUTE: unrelated_node,
                },
            ),
            (
                check_nodes,
                checks_join_node,
                collect_node,
                advisor_node,
            ),
        ],
    )
    return App(name="guardian_offline", root_agent=workflow)
