"""Unit tests for deterministic app-reputation heuristics."""

from guardian.tools.app_reputation import check_app_reputation


def test_known_suspicious_demo_app_is_flagged() -> None:
    result = check_app_reputation("flashlight-helper.example")

    assert result["reputation"] == "suspicious"
    assert result["risk_score"] >= 2


def test_known_trusted_demo_app_is_low_risk() -> None:
    result = check_app_reputation("trusted-bank.example")

    assert result["reputation"] == "trusted"
    assert result["risk_score"] == 0


def test_unknown_app_is_not_claimed_as_safe() -> None:
    result = check_app_reputation("new-random-app.example")

    assert result["reputation"] == "unknown"
    assert result["risk_score"] == 1
