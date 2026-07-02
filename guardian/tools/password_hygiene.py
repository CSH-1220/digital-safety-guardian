"""Fixed, privacy-preserving password hygiene guidance.

This tool takes no input at all: the Guardian never receives a password, so the
strongest privacy guarantee is a function whose signature cannot carry one.
"""

from typing import Literal, TypedDict

PASSWORD_HYGIENE_TIP = (
    "Use a long, unique password; do not reuse it; and store it in a "
    "password manager."
)


class PasswordHygieneCheck(TypedDict):
    """Stable result from the fixed password hygiene check."""

    advice: str
    source: Literal["static"]
    note: str


def check_password_hygiene() -> PasswordHygieneCheck:
    """Return generic password advice without ever receiving a password."""
    return {
        "advice": PASSWORD_HYGIENE_TIP,
        "source": "static",
        "note": PASSWORD_HYGIENE_TIP,
    }
