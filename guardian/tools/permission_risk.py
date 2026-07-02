"""Local permission-risk heuristics for privacy-preserving demos."""

from typing import Literal, NotRequired, TypedDict


class PermissionRiskCheck(TypedDict):
    """Stable result from the local permission-risk heuristic."""

    has_risky_permission: bool
    risky_permissions: list[str]
    app_category: str
    source: Literal["local_heuristic"]
    note: str
    # Present only when at least one known permission term was detected.
    requested_permissions: NotRequired[list[str]]


_PERMISSION_TERMS = {
    "contacts": ("contacts", "address book", "通訊錄"),
    "location": ("location", "gps", "位置"),
    "camera": ("camera", "相機"),
    "microphone": ("microphone", "mic", "麥克風"),
    "photos": ("photos", "gallery", "相簿"),
    "security_settings": (
        "disable two-factor",
        "turn off 2fa",
        "disable 2fa",
        "change security setting",
        "改安全設定",
    ),
    "keylogging": (
        "keyboard input",
        "monitor keyboard",
        "keystroke",
        "keystrokes",
        "keylog",
        "監控鍵盤",
    ),
    "autostart": (
        "start automatically",
        "run at startup",
        "launch at login",
        "at login",
        "auto-start",
        "開機自動",
    ),
    "file_access": (
        "downloads",
        "read files",
        "access files",
        "documents folder",
        "your files",
    ),
}
_UTILITY_HINTS = ("flashlight", "calculator", "qr", "utility", "手電筒")

# Permissions dangerous for *any* app, regardless of what the app claims to be.
_ALWAYS_RISKY = frozenset(
    {"security_settings", "keylogging", "contacts", "autostart", "file_access"}
)
# Permissions that are mainly a red flag when a simple utility app over-asks.
_UTILITY_SENSITIVE = frozenset({"location", "camera", "microphone", "photos"})


def check_permission_risk(
    app_or_domain: str | None,
    raw_context: str | None,
) -> PermissionRiskCheck:
    """Detect overbroad permission requests from local text only."""
    text = f"{app_or_domain or ''} {raw_context or ''}".lower()
    # Fast exit when the text mentions none of the known permission terms.
    if not text.strip() or not any(term in text for terms in _PERMISSION_TERMS.values() for term in terms):
        return {
            "has_risky_permission": False,
            "risky_permissions": [],
            "app_category": _app_category(app_or_domain, raw_context),
            "source": "local_heuristic",
            "note": "No permission-related risk signal found.",
        }

    requested = [
        permission
        for permission, terms in _PERMISSION_TERMS.items()
        if any(term in text for term in terms)
    ]
    app_category = _app_category(app_or_domain, raw_context)
    risky = [
        permission
        for permission in requested
        if permission in _ALWAYS_RISKY
        or (app_category == "utility" and permission in _UTILITY_SENSITIVE)
    ]
    return {
        "has_risky_permission": bool(risky),
        "risky_permissions": risky,
        "requested_permissions": requested,
        "app_category": app_category,
        "source": "local_heuristic",
        "note": (
            "Permission request looks excessive for this app context."
            if risky
            else "Permission request was detected but not clearly excessive."
        ),
    }


def _app_category(app_or_domain: str | None, raw_context: str | None) -> str:
    text = f"{app_or_domain or ''} {raw_context or ''}".lower()
    if any(hint in text for hint in _UTILITY_HINTS):
        return "utility"
    if "bank" in text or "finance" in text:
        return "financial"
    return "unknown"
