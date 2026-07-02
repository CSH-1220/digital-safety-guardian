"""Synthetic email-leak lookup tool for the Guardian workflow."""

from typing import Literal, TypedDict

from guardian.breach_db import lookup_email


class EmailLeakCheck(TypedDict):
    """Stable result from a synthetic email-leak check."""

    found: bool
    breaches: list[str]
    source: Literal["synthetic"]
    note: str


def check_email_leak(email: str | None) -> EmailLeakCheck:
    """Look up a supplied email without accepting passwords or other secrets."""
    if email is None or not email.strip():
        return {
            "found": False,
            "breaches": [],
            "source": "synthetic",
            "note": "no email provided",
        }

    return {**lookup_email(email), "note": ""}
