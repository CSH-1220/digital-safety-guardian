"""Tests for the Guardian MCP tool boundary."""

import asyncio
import inspect

from guardian.mcp_server import (
    check_app_reputation_tool,
    check_domain_reputation_tool,
    check_email_leak_tool,
    check_password_hygiene_tool,
    check_permission_risk_tool,
    check_url_phishing_tool,
    mcp,
)


def test_email_tool_wraps_synthetic_leak_logic() -> None:
    """The MCP-facing wrapper preserves the synthetic breach lookup result."""
    result = check_email_leak_tool("leaked@example.com")

    assert result["found"] is True
    assert result["source"] == "synthetic"


def test_domain_tool_returns_the_domain_reputation_shape() -> None:
    """A missing domain stays on the deterministic, no-network safe path."""
    result = check_domain_reputation_tool(None)

    assert "on_threatlist" in result
    assert result["on_threatlist"] is False


def test_url_phishing_tool_flags_a_suspicious_link() -> None:
    """The MCP wrapper preserves the URL phishing heuristic result."""
    result = check_url_phishing_tool(
        "https://phishy-demo.test/login/verify", "urgent: verify now"
    )

    assert result["has_phishing_signals"] is True
    assert result["source"] == "local_heuristic"


def test_permission_risk_tool_flags_a_utility_wanting_contacts() -> None:
    """The MCP wrapper preserves the permission-risk heuristic result."""
    result = check_permission_risk_tool(
        "flashlight-helper.example", "This flashlight app wants to read contacts."
    )

    assert result["has_risky_permission"] is True
    assert "contacts" in result["risky_permissions"]


def test_app_reputation_tool_flags_a_suspicious_app() -> None:
    """The MCP wrapper preserves the synthetic app-reputation result."""
    result = check_app_reputation_tool("phishy-demo.test")

    assert result["reputation"] == "suspicious"


def test_password_hygiene_tool_returns_fixed_advice_and_takes_no_input() -> None:
    """The strongest privacy guarantee: the tool cannot receive a password."""
    result = check_password_hygiene_tool()

    assert "reuse" in result["note"].lower()
    assert inspect.signature(check_password_hygiene_tool).parameters == {}


def test_server_registers_all_six_guardian_tools() -> None:
    """FastMCP exposes every check as a tool without starting stdio."""
    registered_tools = asyncio.run(mcp.list_tools())

    assert {tool.name for tool in registered_tools} == {
        "check_domain_reputation_tool",
        "check_email_leak_tool",
        "check_url_phishing_tool",
        "check_permission_risk_tool",
        "check_app_reputation_tool",
        "check_password_hygiene_tool",
    }


def test_mcp_tool_wrappers_never_accept_passwords_or_secrets() -> None:
    """The MCP boundary keeps the Guardian's privacy guarantee explicit."""
    parameter_names = {
        *inspect.signature(check_email_leak_tool).parameters,
        *inspect.signature(check_domain_reputation_tool).parameters,
        *inspect.signature(check_url_phishing_tool).parameters,
        *inspect.signature(check_permission_risk_tool).parameters,
        *inspect.signature(check_app_reputation_tool).parameters,
        *inspect.signature(check_password_hygiene_tool).parameters,
    }

    assert "password" not in parameter_names
    assert "secret" not in parameter_names
