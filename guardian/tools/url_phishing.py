"""Local URL phishing heuristics for demo safety checks."""

from typing import Literal, TypedDict
from urllib.parse import urlparse


class URLPhishingCheck(TypedDict):
    """Stable result from the local URL phishing heuristic."""

    has_phishing_signals: bool
    risk_score: int
    signals: list[str]
    source: Literal["local_heuristic"]
    note: str

_URGENT_TERMS = (
    "urgent",
    "verify",
    "problem",
    "issue",
    "suspended",
    "limited time",
    "act now",
)
_SENSITIVE_PATH_TERMS = (
    "login",
    "verify",
    "resolve",
    "delivery",
    "account",
    "password",
)
_DEMO_RISKY_DOMAINS = {
    "phishy-demo.test",
    "parcel-alert-demo.test",
}


def check_url_phishing(
    url: str | None, raw_context: str | None = None
) -> URLPhishingCheck:
    """Return deterministic phishing signals without calling the network."""
    if not url or not url.strip():
        return {
            "has_phishing_signals": False,
            "risk_score": 0,
            "signals": [],
            "source": "local_heuristic",
            "note": "No URL provided.",
        }

    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    context = (raw_context or "").lower()
    signals: list[str] = []

    if host in _DEMO_RISKY_DOMAINS or "phish" in host:
        signals.append("suspicious_domain")
    if any(term in context for term in _URGENT_TERMS):
        signals.append("urgent_language")
    if any(term in path for term in _SENSITIVE_PATH_TERMS):
        signals.append("sensitive_path")
    if parsed.scheme and parsed.scheme != "https":
        signals.append("non_https")
    if host.count("-") >= 2:
        signals.append("hyphenated_domain")
    if host.startswith("xn--"):
        signals.append("punycode_domain")

    # Each heuristic contributes one point; two or more independent signals is
    # our threshold for treating the link as phishy.
    risk_score = min(len(signals), 5)
    return {
        "has_phishing_signals": risk_score >= 2,
        "risk_score": risk_score,
        "signals": signals,
        "source": "local_heuristic",
        "note": (
            "Potential phishing signals found."
            if risk_score >= 2
            else "No strong phishing signals found."
        ),
    }
