"""Canonical ADK workflow state keys, shared across every node.

Each key is declared exactly once here so a rename cannot silently desync one
node from another. Nodes import these names instead of re-typing the string.
"""

# The validated RiskEvent written by intake and read by the checks.
RISK_EVENT = "risk_event"
# The RiskAssessment produced by assess_risk and consumed downstream.
ASSESSMENT = "assessment"
# The fan-in list of RiskFindings produced by collect_findings.
FINDINGS = "findings"
# The advisor LLM's raw GuardianAdviceDraft, before deterministic finalization.
GUARDIAN_ADVICE_DRAFT = "guardian_advice_draft"
# The strict, user-facing GuardianAdvice written by finalize_advice.
GUARDIAN_ADVICE = "guardian_advice"
