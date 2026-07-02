"""Unit tests for deterministic permission-risk heuristics."""

from guardian.tools.permission_risk import check_permission_risk


def test_contacts_permission_for_flashlight_is_high_risk() -> None:
    result = check_permission_risk(
        app_or_domain="flashlight-helper.example",
        raw_context="A flashlight app is asking for permission to read contacts.",
    )

    assert result["has_risky_permission"] is True
    assert "contacts" in result["risky_permissions"]
    assert result["app_category"] == "utility"


def test_security_settings_change_is_detected() -> None:
    result = check_permission_risk(
        app_or_domain="unknown-app.example",
        raw_context="The app asks the user to disable two-factor authentication.",
    )

    assert result["has_risky_permission"] is True
    assert "security_settings" in result["risky_permissions"]


def test_keylogging_request_is_risky() -> None:
    """Monitoring keyboard input is a spyware-grade signal for any app."""
    result = check_permission_risk(
        app_or_domain="free-pdf-converter.example",
        raw_context="The app wants to monitor keyboard input for shortcuts.",
    )

    assert result["has_risky_permission"] is True
    assert "keylogging" in result["risky_permissions"]


def test_contacts_are_risky_regardless_of_app_category() -> None:
    """Any app asking for contacts is suspicious, not only utility apps."""
    result = check_permission_risk(
        app_or_domain="free-pdf-converter.example",
        raw_context="The app is asking to read contacts.",
    )

    assert result["has_risky_permission"] is True
    assert "contacts" in result["risky_permissions"]


def test_use_case_3_pdf_converter_flags_all_overreach() -> None:
    """The full UC3 spyware-like request must surface as risky."""
    result = check_permission_risk(
        app_or_domain="free-pdf-converter.example",
        raw_context=(
            "A PDF converter is asking to access Downloads, read contacts, "
            "start automatically at login, and monitor keyboard input for shortcuts."
        ),
    )

    assert result["has_risky_permission"] is True
    assert {"keylogging", "contacts", "autostart", "file_access"} <= set(
        result["risky_permissions"]
    )


def test_missing_context_is_graceful() -> None:
    result = check_permission_risk(app_or_domain=None, raw_context=None)

    assert result["has_risky_permission"] is False
    assert result["risky_permissions"] == []
    assert "no permission" in result["note"].lower()
