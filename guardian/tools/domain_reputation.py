"""Keyless domain-age and synthetic threat-list reputation lookup."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypedDict

import httpx

_RDAP_URL_TEMPLATE = "https://rdap.org/domain/{domain}"
_REQUEST_TIMEOUT_SECONDS = 5.0
_SOURCE: Literal["rdap+local"] = "rdap+local"
_UNAVAILABLE_NOTE = "reputation unavailable"
_THREATLIST_PATH = Path(__file__).parent.parent / "data" / "threatlist.txt"
_THREATS = frozenset(
    line.strip().lower()
    for line in _THREATLIST_PATH.read_text(encoding="utf-8").splitlines()
    if line.strip()
)


class DomainReputationCheck(TypedDict):
    """Stable result from a domain reputation check."""

    domain_age_days: int | None
    on_threatlist: bool
    source: Literal["rdap+local"]
    note: str


def _unavailable_result() -> DomainReputationCheck:
    return {
        "domain_age_days": None,
        "on_threatlist": False,
        "source": _SOURCE,
        "note": _UNAVAILABLE_NOTE,
    }


def _normalize_domain(domain: str | None) -> str | None:
    """Return a canonical bare domain, rejecting URLs, paths, ports, and IPs."""
    if domain is None:
        return None

    candidate = domain.strip().lower()
    # Reject anything with URL/port/userinfo punctuation — we want a bare domain.
    if not candidate or any(char in candidate for char in ":/@?#\\"):
        return None

    try:
        # Encode internationalized domains to ASCII (punycode) for consistent checks.
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(normalized) > 253 or "." not in normalized:
        return None

    # Enforce DNS label rules: 1-63 chars, alphanumeric/hyphen only, no leading
    # or trailing hyphen. Anything else isn't a real domain.
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isascii() and (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        return None

    return normalized


def _rdap_age_days(domain: str) -> int | None:
    """Fetch RDAP registration data for one already-validated bare domain."""
    response = httpx.get(
        _RDAP_URL_TEMPLATE.format(domain=domain), timeout=_REQUEST_TIMEOUT_SECONDS
    )
    response.raise_for_status()
    for event in response.json().get("events", []):
        if event.get("eventAction") == "registration":
            registered_at = datetime.fromisoformat(
                event["eventDate"].replace("Z", "+00:00")
            )
            return (datetime.now(UTC) - registered_at).days
    return None


def check_domain_reputation(domain: str | None) -> DomainReputationCheck:
    """Check a bare domain using RDAP and the bundled synthetic threat list."""
    normalized_domain = _normalize_domain(domain)
    if normalized_domain is None:
        return _unavailable_result()

    on_threatlist = normalized_domain in _THREATS
    try:
        domain_age_days = _rdap_age_days(normalized_domain)
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return {
            "domain_age_days": None,
            "on_threatlist": on_threatlist,
            "source": _SOURCE,
            "note": _UNAVAILABLE_NOTE,
        }

    return {
        "domain_age_days": domain_age_days,
        "on_threatlist": on_threatlist,
        "source": _SOURCE,
        "note": "",
    }
