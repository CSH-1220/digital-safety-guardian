"""Unit tests for deterministic, privacy-preserving check nodes."""

from types import SimpleNamespace

from guardian.contracts import RiskAssessment
from guardian.nodes import checks
from guardian.nodes.checks import (
    finding_for_app_reputation,
    finding_for_domain,
    finding_for_email,
    finding_for_permission,
    finding_for_url,
    password_hygiene_finding,
)


def test_email_found_is_high() -> None:
    finding = finding_for_email(
        {"found": True, "breaches": ["X"], "source": "synthetic", "note": ""}
    )

    assert finding.check == "email_leak"
    assert finding.severity == "high"


def test_email_clean_is_low() -> None:
    finding = finding_for_email(
        {"found": False, "breaches": [], "source": "synthetic", "note": ""}
    )

    assert finding.severity == "low"


def test_new_domain_is_medium() -> None:
    finding = finding_for_domain(
        {
            "domain_age_days": 30,
            "on_threatlist": False,
            "source": "rdap+local",
            "note": "",
        }
    )

    assert finding.severity == "medium"


def test_threatlisted_domain_is_high() -> None:
    finding = finding_for_domain(
        {
            "domain_age_days": 800,
            "on_threatlist": True,
            "source": "rdap+local",
            "note": "",
        }
    )

    assert finding.severity == "high"


def test_unknown_domain_age_is_unknown() -> None:
    finding = finding_for_domain(
        {
            "domain_age_days": None,
            "on_threatlist": False,
            "source": "rdap+local",
            "note": "reputation unavailable",
        }
    )

    assert finding.severity == "unknown"


def test_password_hygiene_is_fixed_advice() -> None:
    finding = password_hygiene_finding()

    assert finding.check == "password_hygiene"
    assert "reuse" in finding.note.lower()


def test_url_phishing_signal_is_high() -> None:
    finding = finding_for_url(
        {
            "has_phishing_signals": True,
            "risk_score": 4,
            "signals": ["urgent_language"],
            "source": "local_heuristic",
            "note": "Suspicious link.",
        }
    )

    assert finding.check == "url_phishing"
    assert finding.severity == "high"


def test_permission_risk_for_contacts_is_high() -> None:
    finding = finding_for_permission(
        {
            "has_risky_permission": True,
            "risky_permissions": ["contacts"],
            "app_category": "utility",
            "source": "local_heuristic",
            "note": "Contacts permission is risky for this app.",
        }
    )

    assert finding.check == "permission_risk"
    assert finding.severity == "high"


def test_permission_risk_for_security_settings_is_high() -> None:
    """Disabling 2FA is the most dangerous permission signal — it must be high."""
    finding = finding_for_permission(
        {
            "has_risky_permission": True,
            "risky_permissions": ["security_settings"],
            "app_category": "unknown",
            "source": "local_heuristic",
            "note": "Request to disable two-factor authentication.",
        }
    )

    assert finding.check == "permission_risk"
    assert finding.severity == "high"


def test_permission_risk_for_keylogging_is_high() -> None:
    """Keyboard monitoring must escalate to high severity for any app."""
    finding = finding_for_permission(
        {
            "has_risky_permission": True,
            "risky_permissions": ["keylogging", "autostart"],
            "app_category": "unknown",
            "source": "local_heuristic",
            "note": "Keylogging request.",
        }
    )

    assert finding.severity == "high"


def test_unknown_app_reputation_is_medium() -> None:
    finding = finding_for_app_reputation(
        {
            "reputation": "unknown",
            "risk_score": 1,
            "source": "synthetic",
            "note": "No local reputation record.",
        }
    )

    assert finding.check == "app_reputation"
    assert finding.severity == "medium"


def test_omitted_check_writes_no_finding() -> None:
    context = _context_for(["email_leak"])

    event = checks.reputation_check(context)

    assert event.actions.state_delta == {}


def test_selected_email_check_appends_a_finding_without_mutating_context(
    monkeypatch,
) -> None:
    context = _context_for(["email_leak"], email="leaked@example.com")
    monkeypatch.setattr(
        checks,
        "check_email_leak",
        lambda _: {"found": True, "breaches": ["Demo"], "source": "synthetic", "note": ""},
    )

    event = checks.leak_check(context)

    assert context.state["findings"] == []
    assert event.actions.state_delta["email_leak_finding"]["severity"] == "high"


def test_tool_failure_becomes_unknown_finding(monkeypatch) -> None:
    context = _context_for(["domain_reputation"], domain="example.com")
    monkeypatch.setattr(checks, "check_domain_reputation", _raise_network_error)

    event = checks.reputation_check(context)

    finding = event.actions.state_delta["domain_reputation_finding"]
    assert finding["severity"] == "unknown"
    assert "couldn't verify" in finding["note"].lower()


def test_selected_url_check_writes_independent_finding(monkeypatch) -> None:
    context = _context_for(
        ["url_phishing"],
        domain="parcel-alert-demo.test",
        url="https://parcel-alert-demo.test/resolve",
    )
    monkeypatch.setattr(
        checks,
        "check_url_phishing",
        lambda *_args, **_kwargs: {
            "has_phishing_signals": True,
            "risk_score": 4,
            "signals": ["urgent_language"],
            "source": "local_heuristic",
            "note": "Suspicious link.",
        },
    )

    event = checks.url_phishing_check(context)

    assert event.actions.state_delta["url_phishing_finding"]["severity"] == "high"


def test_selected_permission_check_writes_independent_finding(monkeypatch) -> None:
    context = _context_for(["permission_risk"], domain="flashlight-helper.example")
    context.state["risk_event"]["raw_context"] = (
        "A flashlight app is asking to read contacts."
    )
    monkeypatch.setattr(
        checks,
        "check_permission_risk",
        lambda *_args, **_kwargs: {
            "has_risky_permission": True,
            "risky_permissions": ["contacts"],
            "app_category": "utility",
            "source": "local_heuristic",
            "note": "Risky permission.",
        },
    )

    event = checks.permission_risk_check(context)

    assert event.actions.state_delta["permission_risk_finding"]["check"] == (
        "permission_risk"
    )


def test_selected_app_reputation_check_writes_independent_finding(monkeypatch) -> None:
    context = _context_for(["app_reputation"], domain="flashlight-helper.example")
    monkeypatch.setattr(
        checks,
        "check_app_reputation",
        lambda *_args, **_kwargs: {
            "reputation": "suspicious",
            "risk_score": 3,
            "source": "synthetic",
            "note": "Suspicious local reputation.",
        },
    )

    event = checks.app_reputation_check(context)

    assert event.actions.state_delta["app_reputation_finding"]["severity"] == "high"


def test_collect_findings_fans_in_parallel_check_outputs() -> None:
    context = _context_for(["domain_reputation", "email_leak", "password_hygiene"])
    context.state.update(
        {
            "domain_reputation_finding": {
                "check": "domain_reputation",
                "severity": "high",
                "evidence": {"on_threatlist": True},
                "note": "Threatlisted.",
            },
            "email_leak_finding": {
                "check": "email_leak",
                "severity": "low",
                "evidence": {"found": False},
                "note": "Not found.",
            },
            "password_hygiene_finding": {
                "check": "password_hygiene",
                "severity": "low",
                "evidence": {},
                "note": "Use a unique password.",
            },
            "url_phishing_finding": {
                "check": "url_phishing",
                "severity": "high",
                "evidence": {"signals": ["urgent_language"]},
                "note": "Suspicious URL.",
            },
            "permission_risk_finding": {
                "check": "permission_risk",
                "severity": "medium",
                "evidence": {"risky_permissions": ["location"]},
                "note": "Risky permission.",
            },
            "app_reputation_finding": {
                "check": "app_reputation",
                "severity": "medium",
                "evidence": {"reputation": "unknown"},
                "note": "Unknown app.",
            },
        }
    )

    event = checks.collect_findings(context)

    assert [finding["check"] for finding in event.actions.state_delta["findings"]] == [
        "domain_reputation",
        "email_leak",
        "password_hygiene",
        "url_phishing",
        "permission_risk",
        "app_reputation",
    ]


def _context_for(
    relevant_checks: list[str],
    *,
    email: str | None = None,
    domain: str | None = None,
    url: str | None = None,
) -> SimpleNamespace:
    assessment = RiskAssessment(
        has_concern=True,
        risk_description="Test assessment",
        relevant_checks=relevant_checks,
        confidence=1.0,
    )
    return SimpleNamespace(
        state={
            "assessment": assessment.model_dump(),
            "risk_event": {"email": email, "app_or_domain": domain, "url": url},
            "findings": [],
        }
    )


def _raise_network_error(_: str | None) -> dict:
    raise RuntimeError("network unavailable")
