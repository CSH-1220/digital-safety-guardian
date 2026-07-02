"""MCP server exposing the Guardian's six privacy-preserving intelligence tools.

Every deterministic check the workflow runs is also published here as a standard
MCP tool, so the same safety intelligence is reusable by any MCP client. The
workflow itself still calls the underlying tool functions directly for
determinism and speed; this server is an additional, protocol-standard surface.
"""

# Confirmed against the installed mcp 1.x source:
# `from mcp.server.fastmcp import FastMCP`, `@mcp.tool()`, and
# `mcp.run(transport="stdio")` are the FastMCP server APIs.
from mcp.server.fastmcp import FastMCP

from guardian.tools.app_reputation import AppReputationCheck, check_app_reputation
from guardian.tools.domain_reputation import (
    DomainReputationCheck,
    check_domain_reputation,
)
from guardian.tools.email_leak import EmailLeakCheck, check_email_leak
from guardian.tools.password_hygiene import (
    PasswordHygieneCheck,
    check_password_hygiene,
)
from guardian.tools.permission_risk import PermissionRiskCheck, check_permission_risk
from guardian.tools.url_phishing import URLPhishingCheck, check_url_phishing

mcp = FastMCP("guardian-intel")


@mcp.tool()
def check_email_leak_tool(email: str | None) -> EmailLeakCheck:
    """Check an email against the Guardian's synthetic breach database."""
    return check_email_leak(email)


@mcp.tool()
def check_domain_reputation_tool(domain: str | None) -> DomainReputationCheck:
    """Check a domain with keyless RDAP and the local synthetic threat list."""
    return check_domain_reputation(domain)


@mcp.tool()
def check_url_phishing_tool(
    url: str | None, raw_context: str | None = None
) -> URLPhishingCheck:
    """Score a link for phishing signals using local, no-network heuristics."""
    return check_url_phishing(url, raw_context)


@mcp.tool()
def check_permission_risk_tool(
    app_or_domain: str | None, raw_context: str | None = None
) -> PermissionRiskCheck:
    """Flag overbroad app-permission requests from local text heuristics only."""
    return check_permission_risk(app_or_domain, raw_context)


@mcp.tool()
def check_app_reputation_tool(app_or_domain: str | None) -> AppReputationCheck:
    """Look up an app or domain in the Guardian's synthetic reputation data."""
    return check_app_reputation(app_or_domain)


@mcp.tool()
def check_password_hygiene_tool() -> PasswordHygieneCheck:
    """Return generic password hygiene advice; never receives a password."""
    return check_password_hygiene()


if __name__ == "__main__":
    mcp.run(transport="stdio")
