"""Tests for the synthetic breach database lookup."""

import pytest

from guardian.breach_db import lookup_email


def test_known_email_is_found_in_synthetic_data() -> None:
    result = lookup_email("leaked@example.com")

    assert result == {
        "found": True,
        "breaches": ["FakeShop 2021", "DemoSocial 2023"],
        "source": "synthetic",
    }


def test_unknown_email_is_not_found() -> None:
    result = lookup_email("nobody@nowhere.com")

    assert result == {"found": False, "breaches": [], "source": "synthetic"}


@pytest.mark.parametrize("email", ["LEAKED@example.com", "  leaked@example.com  "])
def test_lookup_normalizes_case_and_surrounding_whitespace(email: str) -> None:
    result = lookup_email(email)

    assert result["found"] is True


def test_lookup_returns_a_fresh_breach_list_per_call() -> None:
    first_result = lookup_email("leaked@example.com")
    first_result["breaches"].append("Caller-added value")

    second_result = lookup_email("leaked@example.com")

    assert second_result["breaches"] == ["FakeShop 2021", "DemoSocial 2023"]
