"""Self-gated deterministic safety checks for the ADK workflow."""

import logging
from collections.abc import Callable, Mapping
from typing import Any

from google.adk.agents.context import Context
from google.adk.events import Event
from pydantic import ValidationError

from guardian.contracts import CheckId, RiskAssessment, RiskEvent, RiskFinding, Severity
from guardian.state_keys import ASSESSMENT, FINDINGS, RISK_EVENT
from guardian.tools.app_reputation import check_app_reputation
from guardian.tools.domain_reputation import check_domain_reputation
from guardian.tools.email_leak import check_email_leak
from guardian.tools.password_hygiene import PASSWORD_HYGIENE_TIP
from guardian.tools.permission_risk import check_permission_risk
from guardian.tools.url_phishing import check_url_phishing

_ASSESSMENT_KEY = ASSESSMENT
_EVENT_KEY = RISK_EVENT
_FINDINGS_KEY = FINDINGS
_DOMAIN_FINDING_KEY = "domain_reputation_finding"
_EMAIL_FINDING_KEY = "email_leak_finding"
_PASSWORD_FINDING_KEY = "password_hygiene_finding"
_URL_FINDING_KEY = "url_phishing_finding"
_PERMISSION_FINDING_KEY = "permission_risk_finding"
_APP_FINDING_KEY = "app_reputation_finding"
_DOMAIN_CHECK: CheckId = "domain_reputation"
_EMAIL_CHECK: CheckId = "email_leak"
_PASSWORD_CHECK: CheckId = "password_hygiene"
_URL_CHECK: CheckId = "url_phishing"
_PERMISSION_CHECK: CheckId = "permission_risk"
_APP_CHECK: CheckId = "app_reputation"
_FINDING_KEYS = (
    _DOMAIN_FINDING_KEY,
    _EMAIL_FINDING_KEY,
    _PASSWORD_FINDING_KEY,
    _URL_FINDING_KEY,
    _PERMISSION_FINDING_KEY,
    _APP_FINDING_KEY,
)
_UNKNOWN_TOOL_NOTE = "Couldn't verify this check right now."
logger = logging.getLogger(__name__)
# Permissions sensitive enough to warrant "high" severity on their own, before
# weighing app context. Extend this set as new high-risk scopes are added.
# "security_settings" (e.g. disabling 2FA) and "keylogging" (monitoring keyboard
# input) are spyware-grade signals, so they escalate regardless of app category.
_HIGH_SEVERITY_PERMISSIONS = frozenset({"contacts", "security_settings", "keylogging"})


def finding_for_email(result: Mapping[str, Any]) -> RiskFinding:
    """Convert a synthetic breach lookup result into a deterministic finding."""
    found = bool(result.get("found", False))
    return RiskFinding(
        check=_EMAIL_CHECK,
        severity="high" if found else "low",
        evidence=dict(result),
        note=(
            "This email appears in a known leak — change reused passwords."
            if found
            else "Email not found in our synthetic leak list."
        ),
    )


def finding_for_domain(result: Mapping[str, Any]) -> RiskFinding:
    """Map domain reputation evidence to a conservative severity."""
    age_days = result.get("domain_age_days")
    if bool(result.get("on_threatlist", False)):
        severity: Severity = "high"
        note = "This domain appears on the bundled threat list."
    elif age_days is None:
        severity = "unknown"
        note = "Domain reputation could not be verified."
    elif isinstance(age_days, int) and age_days < 90:
        severity = "medium"
        note = "This domain is relatively new, so use extra caution."
    else:
        severity = "low"
        note = "No bundled threat-list match was found."

    return RiskFinding(
        check=_DOMAIN_CHECK,
        severity=severity,
        evidence=dict(result),
        note=note,
    )


def password_hygiene_finding() -> RiskFinding:
    """Return fixed password guidance without receiving any password data."""
    return RiskFinding(
        check=_PASSWORD_CHECK,
        severity="low",
        evidence={},
        note=PASSWORD_HYGIENE_TIP,
    )


def finding_for_url(result: Mapping[str, Any]) -> RiskFinding:
    """Map URL phishing heuristic evidence to a conservative finding."""
    score = result.get("risk_score", 0)
    if bool(result.get("has_phishing_signals", False)) and score >= 3:
        severity: Severity = "high"
        note = "This link has multiple phishing-like signals."
    elif bool(result.get("has_phishing_signals", False)):
        severity = "medium"
        note = "This link has phishing-like signals."
    else:
        severity = "low"
        note = "No strong phishing signals were found in the URL."
    return RiskFinding(
        check=_URL_CHECK,
        severity=severity,
        evidence=dict(result),
        note=note,
    )


def finding_for_permission(result: Mapping[str, Any]) -> RiskFinding:
    """Map permission evidence to a privacy-risk finding."""
    risky_permissions = result.get("risky_permissions", [])
    has_high_risk = any(p in _HIGH_SEVERITY_PERMISSIONS for p in risky_permissions)
    if bool(result.get("has_risky_permission", False)) and has_high_risk:
        severity: Severity = "high"
        note = "The requested permission looks excessive for this app context."
    elif bool(result.get("has_risky_permission", False)):
        severity = "medium"
        note = "The requested permission or setting change deserves caution."
    else:
        severity = "low"
        note = "No clearly excessive permission request was detected."
    return RiskFinding(
        check=_PERMISSION_CHECK,
        severity=severity,
        evidence=dict(result),
        note=note,
    )


def finding_for_app_reputation(result: Mapping[str, Any]) -> RiskFinding:
    """Map synthetic app reputation evidence to a finding."""
    reputation = result.get("reputation")
    score = result.get("risk_score", 0)
    if reputation == "suspicious" or score >= 2:
        severity: Severity = "high"
        note = "The app or domain is suspicious in the local demo reputation data."
    elif reputation == "unknown":
        severity = "medium"
        note = "The app or domain is not known locally; treat it as unverified."
    else:
        severity = "low"
        note = "The app or domain is trusted in the local demo reputation data."
    return RiskFinding(
        check=_APP_CHECK,
        severity=severity,
        evidence=dict(result),
        note=note,
    )


def _run_check(check_id: CheckId, produce: Callable[[], RiskFinding]) -> RiskFinding:
    """Run a check's tool + severity mapping, degrading safely on failure.

    Any exception becomes an "unknown" finding so one tool failing never breaks
    the graph — but we log it first, so a real bug (e.g. an AttributeError from a
    bad refactor) stays visible instead of silently degrading like an expected
    external-service outage.
    """
    try:
        return produce()
    except Exception:
        logger.exception("%s check failed; returning unknown finding", check_id)
        return _unknown_finding(check_id)


def reputation_check(ctx: Context) -> Event:
    """Run domain reputation only when the assessment selected that check."""
    if not _is_selected(ctx, _DOMAIN_CHECK):
        return Event(state={})

    domain = _target_domain(ctx)
    finding = _run_check(
        _DOMAIN_CHECK, lambda: finding_for_domain(check_domain_reputation(domain))
    )
    return _single_finding_event(_DOMAIN_FINDING_KEY, finding)


def leak_check(ctx: Context) -> Event:
    """Run synthetic email-leak lookup only when the assessment selected it."""
    if not _is_selected(ctx, _EMAIL_CHECK):
        return Event(state={})

    email = _target_email(ctx)
    finding = _run_check(
        _EMAIL_CHECK, lambda: finding_for_email(check_email_leak(email))
    )
    return _single_finding_event(_EMAIL_FINDING_KEY, finding)


def password_tips(ctx: Context) -> Event:
    """Append fixed hygiene guidance only when the assessment selected it."""
    if not _is_selected(ctx, _PASSWORD_CHECK):
        return Event(state={})

    return _single_finding_event(_PASSWORD_FINDING_KEY, password_hygiene_finding())


def url_phishing_check(ctx: Context) -> Event:
    """Run URL phishing heuristics only when the assessment selected them."""
    if not _is_selected(ctx, _URL_CHECK):
        return Event(state={})

    event = _risk_event_from(ctx)
    finding = _run_check(
        _URL_CHECK,
        lambda: finding_for_url(check_url_phishing(event.url, event.raw_context)),
    )
    return _single_finding_event(_URL_FINDING_KEY, finding)


def permission_risk_check(ctx: Context) -> Event:
    """Run permission-risk heuristics only when selected."""
    if not _is_selected(ctx, _PERMISSION_CHECK):
        return Event(state={})

    event = _risk_event_from(ctx)
    finding = _run_check(
        _PERMISSION_CHECK,
        lambda: finding_for_permission(
            check_permission_risk(event.app_or_domain, event.raw_context)
        ),
    )
    return _single_finding_event(_PERMISSION_FINDING_KEY, finding)


def app_reputation_check(ctx: Context) -> Event:
    """Run local synthetic app reputation only when selected."""
    if not _is_selected(ctx, _APP_CHECK):
        return Event(state={})

    finding = _run_check(
        _APP_CHECK,
        lambda: finding_for_app_reputation(check_app_reputation(_target_domain(ctx))),
    )
    return _single_finding_event(_APP_FINDING_KEY, finding)


def collect_findings(ctx: Context) -> Event:
    """Fan-in selected check outputs into the standard findings list."""
    # Only checks that were selected actually wrote their finding key, so we walk
    # the known keys and keep the ones present — order stays stable and gated-out
    # checks are simply absent.
    findings = [
        finding.model_dump() if isinstance(finding, RiskFinding) else dict(finding)
        for key in _FINDING_KEYS
        if isinstance((finding := ctx.state.get(key)), (RiskFinding, Mapping))
    ]
    return Event(state={_FINDINGS_KEY: findings})


def _is_selected(ctx: Context, check_id: str) -> bool:
    assessment = _assessment_from(ctx)
    return assessment is not None and check_id in assessment.relevant_checks


def _assessment_from(ctx: Context) -> RiskAssessment | None:
    try:
        return RiskAssessment.model_validate(ctx.state.get(_ASSESSMENT_KEY))
    except ValidationError:
        return None


def _target_domain(ctx: Context) -> str | None:
    """Prefer the domain the assessor extracted from free text; else the event."""
    assessment = _assessment_from(ctx)
    if assessment and assessment.extracted_domain:
        return assessment.extracted_domain
    return _risk_event_from(ctx).app_or_domain


def _target_email(ctx: Context) -> str | None:
    """Prefer the email the assessor extracted from free text; else the event."""
    assessment = _assessment_from(ctx)
    if assessment and assessment.extracted_email:
        return assessment.extracted_email
    return _risk_event_from(ctx).email


def _risk_event_from(ctx: Context) -> RiskEvent:
    event_data = ctx.state.get(_EVENT_KEY, {})
    try:
        return RiskEvent.model_validate(event_data)
    except ValidationError:
        return RiskEvent()


def _single_finding_event(state_key: str, finding: RiskFinding) -> Event:
    return Event(state={state_key: finding.model_dump()})


def _unknown_finding(check_id: str) -> RiskFinding:
    return RiskFinding(
        check=check_id,
        severity="unknown",
        evidence={"error": "tool unavailable"},
        note=_UNKNOWN_TOOL_NOTE,
    )
