"""Read-only lookups against the project's explicitly synthetic breach data."""

import json
from pathlib import Path
from typing import Literal, TypedDict


class BreachLookup(TypedDict):
    """The stable response shape for a synthetic breach lookup."""

    found: bool
    breaches: list[str]
    source: Literal["synthetic"]


_DB_PATH = Path(__file__).parent / "data" / "synthetic_breach_db.json"


def _load_breach_database() -> dict[str, tuple[str, ...]]:
    """Load and validate the static synthetic records into immutable storage."""
    try:
        raw_database = json.loads(_DB_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Synthetic breach database could not be loaded.") from error

    if not isinstance(raw_database, dict):
        raise RuntimeError("Synthetic breach database must contain an object.")

    database: dict[str, tuple[str, ...]] = {}
    for email, breaches in raw_database.items():
        if not isinstance(email, str) or not isinstance(breaches, list):
            raise RuntimeError("Synthetic breach database has an invalid record.")
        if not all(isinstance(breach, str) for breach in breaches):
            raise RuntimeError("Synthetic breach database has an invalid breach name.")
        database[email.strip().lower()] = tuple(breaches)
    return database


_DATABASE = _load_breach_database()


def lookup_email(email: str) -> BreachLookup:
    """Return a case-insensitive lookup result without exposing mutable storage."""
    if not isinstance(email, str):
        raise TypeError("email must be a string")

    breaches = _DATABASE.get(email.strip().lower(), ())
    return {"found": bool(breaches), "breaches": list(breaches), "source": "synthetic"}
