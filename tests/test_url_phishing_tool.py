"""Unit tests for the deterministic URL phishing heuristic."""

from guardian.tools.url_phishing import check_url_phishing


def test_missing_url_is_graceful() -> None:
    result = check_url_phishing(None, raw_context=None)

    assert result["has_phishing_signals"] is False
    assert result["risk_score"] == 0
    assert "no url" in result["note"].lower()


def test_package_issue_link_has_phishing_signals() -> None:
    result = check_url_phishing(
        "https://parcel-alert-demo.test/resolve-delivery-issue",
        raw_context="Your package has a problem. Verify now.",
    )

    assert result["has_phishing_signals"] is True
    assert result["risk_score"] >= 3
    assert "urgent_language" in result["signals"]


def test_benign_url_is_low_signal() -> None:
    result = check_url_phishing(
        "https://docs.example.com/help",
        raw_context="User is reading documentation.",
    )

    assert result["has_phishing_signals"] is False
    assert result["risk_score"] <= 1
