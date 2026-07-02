"""Synthetic app/domain reputation lookup for demo scenarios."""

from typing import Literal, TypedDict


class AppReputationCheck(TypedDict):
    """Stable result from the synthetic app/domain reputation lookup."""

    reputation: str
    risk_score: int
    source: Literal["synthetic"]
    note: str


_REPUTATION_DB = {
    "flashlight-helper.example": {
        "reputation": "suspicious",
        "risk_score": 3,
        "note": "Utility app with suspicious local reputation.",
    },
    "parcel-alert-demo.test": {
        "reputation": "suspicious",
        "risk_score": 3,
        "note": "Demo parcel-alert domain is locally marked suspicious.",
    },
    "phishy-demo.test": {
        "reputation": "suspicious",
        "risk_score": 3,
        "note": "Demo phishing domain is locally marked suspicious.",
    },
    "trusted-bank.example": {
        "reputation": "trusted",
        "risk_score": 0,
        "note": "Trusted demo financial app.",
    },
}


def check_app_reputation(app_or_domain: str | None) -> AppReputationCheck:
    """Return synthetic app/domain reputation without network calls."""
    key = (app_or_domain or "").strip().lower()
    if not key:
        return {
            "reputation": "unknown",
            "risk_score": 1,
            "source": "synthetic",
            "note": "No app or domain provided.",
        }

    result = _REPUTATION_DB.get(
        key,
        {
            "reputation": "unknown",
            "risk_score": 1,
            "note": "No local reputation record; treat as unverified.",
        },
    )
    return {"source": "synthetic", **result}
