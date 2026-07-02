"""Tests for the offline walking skeleton."""

from google.adk.agents import LlmAgent
from google.adk.apps.app import App
from google.adk.workflow import START

from guardian.workflow import build_app


def test_build_app_returns_a_two_llm_workflow_backed_adk_app() -> None:
    app = build_app()

    assert isinstance(app, App)
    # App name must equal the agent directory so playground sessions resolve.
    assert app.name == "guardian"
    node_names = {workflow_node.name for workflow_node in app.root_agent.graph.nodes}
    assert node_names >= {
        START.name,
        "intake",
        "assess_risk",
        "dispatch",
        "reputation_check",
        "leak_check",
        "password_tips",
        "url_phishing_check",
        "permission_risk_check",
        "app_reputation_check",
        "checks_complete",
        "collect_findings",
        "advisor",
        "finalize_advice",
    }
    edge_pairs = {
        (edge.from_node.name, edge.to_node.name, edge.route)
        for edge in app.root_agent.graph.edges
    }
    assert ("dispatch", "url_phishing_check", "concern") in edge_pairs
    assert ("dispatch", "permission_risk_check", "concern") in edge_pairs
    assert ("dispatch", "app_reputation_check", "concern") in edge_pairs
    assert ("url_phishing_check", "checks_complete", None) in edge_pairs
    assert ("permission_risk_check", "checks_complete", None) in edge_pairs
    assert ("app_reputation_check", "checks_complete", None) in edge_pairs
    llm_node_names = {
        workflow_node.name
        for workflow_node in app.root_agent.graph.nodes
        if isinstance(workflow_node, LlmAgent)
    }
    assert llm_node_names == {"assess_risk", "advisor"}
