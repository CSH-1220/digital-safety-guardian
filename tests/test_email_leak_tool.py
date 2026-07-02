"""Tests for the privacy-preserving synthetic email-leak tool."""

import pytest

from guardian.tools.email_leak import check_email_leak


@pytest.mark.parametrize("email", [None, "", "   "])
def test_missing_email_returns_the_safe_response(email: str | None) -> None:
    assert check_email_leak(email) == {
        "found": False,
        "breaches": [],
        "source": "synthetic",
        "note": "no email provided",
    }


def test_known_email_is_delegated_to_the_synthetic_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_lookup = {
        "found": True,
        "breaches": ["FakeShop 2021"],
        "source": "synthetic",
    }
    calls: list[str] = []

    def stub_lookup(email: str) -> dict[str, object]:
        calls.append(email)
        return expected_lookup

    monkeypatch.setattr("guardian.tools.email_leak.lookup_email", stub_lookup)

    result = check_email_leak("leaked@example.com")

    assert calls == ["leaked@example.com"]
    assert result == {**expected_lookup, "note": ""}


def test_tool_has_no_password_or_secret_parameters() -> None:
    assert "password" not in check_email_leak.__annotations__
    assert "secret" not in check_email_leak.__annotations__
