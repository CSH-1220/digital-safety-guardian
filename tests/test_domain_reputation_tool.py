"""Tests for the keyless, privacy-preserving domain reputation tool."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from guardian.tools import domain_reputation as dr


def test_threatlisted_domain_uses_a_local_synthetic_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = datetime.now(UTC) - timedelta(days=10)

    def fake_get(url: str, *, timeout: float) -> httpx.Response:
        assert url == "https://rdap.org/domain/phishy-demo.test"
        assert timeout == 5.0
        return httpx.Response(
            200,
            json={
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": registration.isoformat(),
                    }
                ]
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(dr.httpx, "get", fake_get)

    result = dr.check_domain_reputation("PHISHY-DEMO.TEST")

    assert result["domain_age_days"] == 10
    assert result["on_threatlist"] is True
    assert result["source"] == "rdap+local"
    assert result["note"] == ""


def test_network_failure_returns_the_graceful_unavailable_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_get(url: str, *, timeout: float) -> httpx.Response:
        raise httpx.ConnectError("network unavailable", request=httpx.Request("GET", url))

    monkeypatch.setattr(dr.httpx, "get", fail_get)

    result = dr.check_domain_reputation("example.com")

    assert result == {
        "domain_age_days": None,
        "on_threatlist": False,
        "source": "rdap+local",
        "note": "reputation unavailable",
    }


@pytest.mark.parametrize(
    "domain",
    [None, "", "https://example.com", "example.com/path", "example.com:443", "-bad.test"],
)
def test_invalid_or_missing_domain_never_makes_a_network_request(
    monkeypatch: pytest.MonkeyPatch, domain: str | None
) -> None:
    calls: list[str] = []

    def unexpected_get(url: str, *, timeout: float) -> httpx.Response:
        calls.append(url)
        raise AssertionError("invalid input must not issue an RDAP request")

    monkeypatch.setattr(dr.httpx, "get", unexpected_get)

    result = dr.check_domain_reputation(domain)

    assert calls == []
    assert result == {
        "domain_age_days": None,
        "on_threatlist": False,
        "source": "rdap+local",
        "note": "reputation unavailable",
    }


def test_domain_without_registration_event_returns_an_unknown_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get(url: str, *, timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            json={"events": []},
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(dr.httpx, "get", fake_get)

    result = dr.check_domain_reputation("example.com")

    assert result == {
        "domain_age_days": None,
        "on_threatlist": False,
        "source": "rdap+local",
        "note": "",
    }
