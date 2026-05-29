# engine/workflows/notification_router.py

# Purpose:
# Build stakeholder notification manifests for
# governance workflow routing.
#
# Responsibilities:
# - Determine which stakeholders to notify
# - Build role-aware notification content
# - Build channel-appropriate message formats
# - Produce structured dispatch manifests
# - Log notification routing decisions
#
# IMPORTANT:
# This module NEVER sends notifications directly.
# It produces a manifest for downstream dispatchers.
# Actual dispatch is an integration layer concern.
#
# IMPORTANT:
# Notification routing NEVER influences enforcement.
# Notifications are produced AFTER the deterministic
# decision is resolved.
#
# DISPATCH NOTE:
# The notification manifest is consumed by:
# - Email dispatcher (channel: email)
# - Slack dispatcher (channel: slack)
# - Webhook dispatcher (channel: webhook)
# These dispatchers are Phase 4 integration work.

from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# SEVERITY → PRIORITY MAPPING
# =====================================================

SEVERITY_PRIORITY: dict[str, str] = {
    "critical": "urgent",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}


# =====================================================
# DECISIONS THAT REQUIRE NOTIFICATION
# =====================================================

NOTIFICATION_DECISIONS: frozenset[str] = frozenset(
    {
        "ALLOW_WITH_NOTIFICATION",
        "ALLOW_WITH_APPROVAL_REQUIRED",
        "DENY_WITH_OVERRIDE",
        "DENY",
    }
)


# =====================================================
# ROLE-AWARE CONTENT BUILDERS
# =====================================================


def _build_budget_owner_content(
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict[str, Any],
    evaluation_result: dict[str, Any],
    channel: str,
) -> dict[str, Any]:
    """
    Build notification content for budget owner role.
    Budget owners need: cost impact, authority, risk summary.
    """

    requires_approval: bool = evaluation_result.get("requires_approval", False)
    override_required: bool = evaluation_result.get("override_required", False)
    overall_risk: int = risk_summary.get("overall_risk_score", 0)
    total_findings: int = risk_summary.get("total_findings", 0)

    subject: str = (
        f"[ObsidianWall] Governance Action Required — {policy_name} — {decision}"
    )

    body: str
    if channel == "email":
        if override_required and requires_approval:
            body = (
                f"A deployment was blocked by policy "
                f"'{policy_name}' and requires your approval "
                f"as budget owner before it can proceed.\n\n"
                f"Decision: {decision}\n"
                f"Risk Score: {overall_risk}/100\n"
                f"Severity: {effective_severity.upper()}\n"
                f"Findings: {total_findings}\n\n"
                f"Review the evaluation trace and approve "
                f"or reject this deployment in the "
                f"ObsidianWall governance console."
            )
        elif override_required:
            body = (
                f"A deployment has been blocked by policy "
                f"'{policy_name}'. As budget owner, you have "
                f"override authority and may authorize this "
                f"deployment.\n\n"
                f"Decision: {decision}\n"
                f"Risk Score: {overall_risk}/100\n"
                f"Severity: {effective_severity.upper()}\n"
                f"Findings: {total_findings}\n\n"
                f"Review the evaluation trace and confirm "
                f"or deny the override in the ObsidianWall "
                f"governance console."
            )
        elif decision in ("ALLOW_WITH_NOTIFICATION", "ALLOW_WITH_APPROVAL_REQUIRED"):
            body = (
                f"A deployment within policy '{policy_name}' "
                f"has been authorized but flagged for your "
                f"awareness due to elevated governance severity.\n\n"
                f"Decision: {decision}\n"
                f"Risk Score: {overall_risk}/100\n"
                f"Severity: {effective_severity.upper()}\n"
                f"Findings: {total_findings}\n\n"
                f"No immediate action required. "
                f"Review the full audit record in the "
                f"ObsidianWall governance console."
            )
        else:
            body = (
                f"Governance notification for policy "
                f"'{policy_name}'.\n\n"
                f"Decision: {decision}\n"
                f"Risk Score: {overall_risk}/100\n"
                f"Severity: {effective_severity.upper()}"
            )
    else:
        body = (
            f"*[ObsidianWall]* Policy `{policy_name}` "
            f"decision: *{decision}* | "
            f"Severity: *{effective_severity.upper()}* | "
            f"Risk: {overall_risk}/100 | "
            f"Findings: {total_findings} | "
            + (
                "*Your action is required.*"
                if override_required or requires_approval
                else "Awareness notification."
            )
        )

    return {
        "subject": subject,
        "body": body,
        "requires_action": override_required or requires_approval,
    }


def _build_engineering_lead_content(
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict[str, Any],
    evaluation_result: dict[str, Any],
    channel: str,
) -> dict[str, Any]:
    """
    Build notification content for engineering lead role.
    Engineering leads need: deployment status, recommendations.
    """

    conditions_passed: bool = evaluation_result.get("conditions_passed", False)
    total_findings: int = risk_summary.get("total_findings", 0)
    overall_risk: int = risk_summary.get("overall_risk_score", 0)
    trace: list[Any] = evaluation_result.get("trace", [])

    failed_conditions: list[str] = [
        t.get("condition_id") for t in trace if not t.get("result")
    ]

    subject: str = (
        f"[ObsidianWall] Deployment Governance Update — {policy_name} — {decision}"
    )

    body: str
    if channel == "email":
        if not conditions_passed:
            condition_detail: str = (
                f"Failed conditions: {', '.join(failed_conditions)}."
                if failed_conditions
                else "See evaluation trace for details."
            )
            body = (
                f"A deployment evaluated against policy "
                f"'{policy_name}' was blocked.\n\n"
                f"Decision: {decision}\n"
                f"Severity: {effective_severity.upper()}\n"
                f"Risk Score: {overall_risk}/100\n"
                f"{condition_detail}\n\n"
                f"Review the evaluation trace and remediation "
                f"guidance in the ObsidianWall audit record. "
                f"Contact your budget owner if an override "
                f"or approval is required."
            )
        else:
            body = (
                f"A deployment evaluated against policy "
                f"'{policy_name}' was authorized.\n\n"
                f"Decision: {decision}\n"
                f"Severity: {effective_severity.upper()}\n"
                f"Risk Score: {overall_risk}/100\n"
                f"Findings: {total_findings}\n\n"
                f"Deployment may proceed. Review the "
                f"ObsidianWall recommendations to optimize "
                f"infrastructure configuration."
            )
    else:
        status_emoji: str = "🔴" if not conditions_passed else "🟡"
        body = (
            f"{status_emoji} *[ObsidianWall]* "
            f"Policy `{policy_name}` — *{decision}* | "
            f"Risk: {overall_risk}/100 | "
            f"Severity: {effective_severity.upper()} | "
            + (
                f"Failed: {', '.join(failed_conditions)}"
                if failed_conditions
                else "Deployment authorized with advisory findings."
            )
        )

    return {
        "subject": subject,
        "body": body,
        "requires_action": False,
    }


def _build_finance_admin_content(
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict[str, Any],
    evaluation_result: dict[str, Any],
    channel: str,
) -> dict[str, Any]:
    """
    Build notification content for finance admin role.
    Finance admins need: financial impact, approval requirement.
    """

    requires_approval: bool = evaluation_result.get("requires_approval", False)
    overall_risk: int = risk_summary.get("overall_risk_score", 0)
    highest_analyzer: str | None = risk_summary.get("highest_risk_analyzer")

    subject: str = (
        f"[ObsidianWall] Financial Governance Review — {policy_name} — {decision}"
    )

    body: str
    if channel == "email":
        body = (
            f"A deployment evaluated against financial "
            f"governance policy '{policy_name}' requires "
            f"your review as finance administrator.\n\n"
            f"Decision: {decision}\n"
            f"Severity: {effective_severity.upper()}\n"
            f"Overall Risk Score: {overall_risk}/100\n"
            f"Highest Risk Area: {highest_analyzer or 'unknown'}\n\n"
            + (
                "Your approval is required as part of the "
                "dual-approval governance workflow before "
                "this deployment can proceed.\n\n"
                if requires_approval
                else ""
            )
            + "Review the full financial governance audit "
            "record in the ObsidianWall governance console."
        )
    else:
        body = (
            f"*[ObsidianWall Finance]* Policy `{policy_name}` | "
            f"*{decision}* | "
            f"Severity: *{effective_severity.upper()}* | "
            f"Risk: {overall_risk}/100 | "
            + (
                "*Approval required.*"
                if requires_approval
                else "Awareness notification."
            )
        )

    return {
        "subject": subject,
        "body": body,
        "requires_action": requires_approval,
    }


def _build_generic_content(
    role: str,
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict[str, Any],
    channel: str,
) -> dict[str, Any]:
    """
    Build generic notification content for roles
    without specific content builders.
    """

    overall_risk: int = risk_summary.get("overall_risk_score", 0)

    subject: str = f"[ObsidianWall] Governance Notification — {policy_name}"

    body: str = (
        f"Governance notification for role '{role}'.\n\n"
        f"Policy: {policy_name}\n"
        f"Decision: {decision}\n"
        f"Severity: {effective_severity.upper()}\n"
        f"Risk Score: {overall_risk}/100"
        if channel == "email"
        else (
            f"*[ObsidianWall]* Policy `{policy_name}` — "
            f"*{decision}* | "
            f"Severity: *{effective_severity.upper()}*"
        )
    )

    return {
        "subject": subject,
        "body": body,
        "requires_action": False,
    }


# =====================================================
# ROLE CONTENT DISPATCHER
# =====================================================

ContentBuilder = Any  # callable type alias for role builders

ROLE_CONTENT_BUILDERS: dict[str, ContentBuilder] = {
    "budget_owner": _build_budget_owner_content,
    "engineering_lead": _build_engineering_lead_content,
    "finance_admin": _build_finance_admin_content,
}


def _build_notification(
    target: dict[str, Any],
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict[str, Any],
    evaluation_result: dict[str, Any],
) -> dict[str, Any]:
    """Build a single stakeholder notification."""

    role: str = target.get("role", "unknown")
    channel: str = target.get("channel", "email")
    priority: str = SEVERITY_PRIORITY.get(effective_severity, "medium")

    content_builder = ROLE_CONTENT_BUILDERS.get(role)

    content: dict[str, Any]
    if content_builder:
        content = content_builder(
            decision=decision,
            policy_name=policy_name,
            effective_severity=effective_severity,
            risk_summary=risk_summary,
            evaluation_result=evaluation_result,
            channel=channel,
        )
    else:
        content = _build_generic_content(
            role=role,
            decision=decision,
            policy_name=policy_name,
            effective_severity=effective_severity,
            risk_summary=risk_summary,
            channel=channel,
        )

    return {
        "target_role": role,
        "channel": channel,
        "priority": priority,
        "subject": content["subject"],
        "body": content["body"],
        "requires_action": content["requires_action"],
        "decision": decision,
        "policy": policy_name,
        "effective_severity": effective_severity,
        "dispatch_status": "pending",
    }


# =====================================================
# NOTIFICATION ROUTER
# =====================================================


def route_notifications(
    decision: str,
    effective_severity: str,
    policy_name: str,
    evaluation_result: dict[str, Any],
    risk_summary: dict[str, Any],
    policy_governance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build the complete notification manifest for all
    configured governance stakeholder targets.

    Returns a structured manifest ready for dispatch.
    Actual sending is handled by downstream dispatchers.

    Raises:
        TypeError:  if required inputs are not correct types.
        ValueError: if decision is empty.
    """

    if not isinstance(evaluation_result, dict):
        raise TypeError("evaluation_result must be a dict")

    if not isinstance(risk_summary, dict):
        raise TypeError("risk_summary must be a dict")

    if not isinstance(decision, str) or not decision:
        raise ValueError("decision must be a non-empty string")

    should_notify: bool = decision in NOTIFICATION_DECISIONS

    if not should_notify or not policy_governance:
        manifest: dict[str, Any] = {
            "notifications_triggered": False,
            "notification_count": 0,
            "notifications": [],
            "dispatch_status": "not_required",
            "reason": (
                "Decision does not require notification."
                if not should_notify
                else "No governance configuration found."
            ),
        }

        logger.info(
            "notifications_not_triggered",
            extra={
                "extra": {
                    "decision": decision,
                    "reason": manifest["reason"],
                }
            },
        )

        return manifest

    notification_targets: list[Any] = policy_governance.get("notifications", [])

    if not notification_targets:
        return {
            "notifications_triggered": False,
            "notification_count": 0,
            "notifications": [],
            "dispatch_status": "not_required",
            "reason": "No notification targets configured in governance policy.",
        }

    notifications: list[dict[str, Any]] = []

    for target in notification_targets:
        if not isinstance(target, dict):
            continue

        notifications.append(
            _build_notification(
                target=target,
                decision=decision,
                policy_name=policy_name,
                effective_severity=effective_severity,
                risk_summary=risk_summary,
                evaluation_result=evaluation_result,
            )
        )

    action_required_count: int = sum(
        1 for n in notifications if n.get("requires_action")
    )

    result: dict[str, Any] = {
        "notifications_triggered": True,
        "notification_count": len(notifications),
        "action_required_count": action_required_count,
        "notifications": notifications,
        "dispatch_status": "pending",
    }

    logger.info(
        "notification_manifest_built",
        extra={
            "extra": {
                "decision": decision,
                "policy_name": policy_name,
                "notification_count": len(notifications),
                "action_required_count": action_required_count,
                "effective_severity": effective_severity,
            }
        },
    )

    return result
