
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


from audit.audit_logger import get_logger


logger = get_logger()


# =====================================================
# SEVERITY → PRIORITY MAPPING
# =====================================================

SEVERITY_PRIORITY = {
    "critical":     "urgent",
    "high":         "high",
    "medium":       "medium",
    "low":          "low",
    "informational": "informational",
}


# =====================================================
# DECISIONS THAT REQUIRE NOTIFICATION
# =====================================================

NOTIFICATION_DECISIONS = {
    "ALLOW_WITH_NOTIFICATION",
    "ALLOW_WITH_APPROVAL_REQUIRED",
    "DENY_WITH_OVERRIDE",
    "DENY",
}


# =====================================================
# ROLE-AWARE CONTENT BUILDERS
# =====================================================

def _build_budget_owner_content(
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict,
    evaluation_result: dict,
    channel: str,
) -> dict:
    """
    Build notification content for budget owner role.
    Budget owners need: cost impact, authority, risk summary.
    """

    conditions_passed   = evaluation_result.get(
        "conditions_passed", False
    )
    requires_approval   = evaluation_result.get(
        "requires_approval", False
    )
    override_required   = evaluation_result.get(
        "override_required", False
    )
    overall_risk        = risk_summary.get(
        "overall_risk_score", 0
    )
    total_findings      = risk_summary.get(
        "total_findings", 0
    )

    subject = (
        f"[ObsidianWall] Governance Action Required — "
        f"{policy_name} — {decision}"
    )

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

        elif decision in (
            "ALLOW_WITH_NOTIFICATION",
            "ALLOW_WITH_APPROVAL_REQUIRED"
        ):

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
        # Slack and other channels — concise format
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
        "subject":          subject,
        "body":             body,
        "requires_action":  (
            override_required or requires_approval
        ),
    }


def _build_engineering_lead_content(
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict,
    evaluation_result: dict,
    channel: str,
) -> dict:
    """
    Build notification content for engineering lead role.
    Engineering leads need: deployment status, recommendations.
    """

    conditions_passed   = evaluation_result.get(
        "conditions_passed", False
    )
    total_findings      = risk_summary.get(
        "total_findings", 0
    )
    overall_risk        = risk_summary.get(
        "overall_risk_score", 0
    )
    trace               = evaluation_result.get("trace", [])

    failed_conditions = [
        t.get("condition_id")
        for t in trace
        if not t.get("result")
    ]

    subject = (
        f"[ObsidianWall] Deployment Governance Update — "
        f"{policy_name} — {decision}"
    )

    if channel == "email":

        if not conditions_passed:

            condition_detail = (
                f"Failed conditions: "
                f"{', '.join(failed_conditions)}."
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
        # Slack — concise
        status_emoji = "🔴" if not conditions_passed else "🟡"
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
        "subject":          subject,
        "body":             body,
        "requires_action":  False,
    }


def _build_finance_admin_content(
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict,
    evaluation_result: dict,
    channel: str,
) -> dict:
    """
    Build notification content for finance admin role.
    Finance admins need: financial impact, approval requirement.
    """

    requires_approval   = evaluation_result.get(
        "requires_approval", False
    )
    overall_risk        = risk_summary.get(
        "overall_risk_score", 0
    )
    highest_analyzer    = risk_summary.get(
        "highest_risk_analyzer", "unknown"
    )

    subject = (
        f"[ObsidianWall] Financial Governance Review — "
        f"{policy_name} — {decision}"
    )

    if channel == "email":

        body = (
            f"A deployment evaluated against financial "
            f"governance policy '{policy_name}' requires "
            f"your review as finance administrator.\n\n"
            f"Decision: {decision}\n"
            f"Severity: {effective_severity.upper()}\n"
            f"Overall Risk Score: {overall_risk}/100\n"
            f"Highest Risk Area: {highest_analyzer}\n\n"
            + (
                f"Your approval is required as part of the "
                f"dual-approval governance workflow before "
                f"this deployment can proceed.\n\n"
                if requires_approval
                else ""
            )
            + f"Review the full financial governance audit "
              f"record in the ObsidianWall governance console."
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
        "subject":          subject,
        "body":             body,
        "requires_action":  requires_approval,
    }


def _build_generic_content(
    role: str,
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict,
    channel: str,
) -> dict:
    """
    Build generic notification content for roles
    without specific content builders.
    """

    overall_risk = risk_summary.get("overall_risk_score", 0)

    subject = (
        f"[ObsidianWall] Governance Notification — "
        f"{policy_name}"
    )

    body = (
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
        "subject":          subject,
        "body":             body,
        "requires_action":  False,
    }


# =====================================================
# ROLE CONTENT DISPATCHER
# =====================================================

ROLE_CONTENT_BUILDERS = {
    "budget_owner":     _build_budget_owner_content,
    "engineering_lead": _build_engineering_lead_content,
    "finance_admin":    _build_finance_admin_content,
}


def _build_notification(
    target: dict,
    decision: str,
    policy_name: str,
    effective_severity: str,
    risk_summary: dict,
    evaluation_result: dict,
) -> dict:
    """
    Build a single stakeholder notification.
    """

    role    = target.get("role", "unknown")
    channel = target.get("channel", "email")
    priority = SEVERITY_PRIORITY.get(
        effective_severity, "medium"
    )

    content_builder = ROLE_CONTENT_BUILDERS.get(role)

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
        "target_role":      role,
        "channel":          channel,
        "priority":         priority,
        "subject":          content["subject"],
        "body":             content["body"],
        "requires_action":  content["requires_action"],
        "decision":         decision,
        "policy":           policy_name,
        "effective_severity": effective_severity,

        # Dispatch status — updated by dispatcher
        # when notification is actually sent.
        "dispatch_status":  "pending",
    }


# =====================================================
# NOTIFICATION ROUTER
# =====================================================

def route_notifications(
    decision: str,
    effective_severity: str,
    policy_name: str,
    evaluation_result: dict,
    risk_summary: dict,
    policy_governance: dict | None = None,
) -> dict:
    """
    Build the complete notification manifest for all
    configured governance stakeholder targets.

    Returns a structured manifest ready for dispatch.
    Actual sending is handled by downstream dispatchers.

    Args:
        decision:           The governance decision outcome
        effective_severity: Max of policy and risk severity
        policy_name:        Name of the evaluated policy
        evaluation_result:  Full evaluation result dict
        risk_summary:       Consolidated risk summary
        policy_governance:  Serialized governance config

    Raises:
        TypeError:  if required inputs are not correct types.
        ValueError: if decision is empty.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(evaluation_result, dict):
        raise TypeError("evaluation_result must be a dict")

    if not isinstance(risk_summary, dict):
        raise TypeError("risk_summary must be a dict")

    if not isinstance(decision, str) or not decision:
        raise ValueError(
            "decision must be a non-empty string"
        )

    # =================================================
    # DETERMINE IF NOTIFICATIONS SHOULD FIRE
    # =================================================

    # Always notify on DENY and DENY_WITH_OVERRIDE.
    # Notify on ALLOW_WITH_* based on governance config.
    # Do not notify on plain ALLOW.

    should_notify = decision in NOTIFICATION_DECISIONS

    if not should_notify or not policy_governance:

        manifest = {
            "notifications_triggered":  False,
            "notification_count":       0,
            "notifications":            [],
            "dispatch_status":          "not_required",
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
                    "decision":     decision,
                    "reason":       manifest["reason"],
                }
            }
        )

        return manifest

    # =================================================
    # BUILD NOTIFICATION MANIFEST
    # =================================================

    notification_targets = policy_governance.get(
        "notifications", []
    )

    if not notification_targets:

        return {
            "notifications_triggered":  False,
            "notification_count":       0,
            "notifications":            [],
            "dispatch_status":          "not_required",
            "reason": (
                "No notification targets configured "
                "in governance policy."
            ),
        }

    notifications = []

    for target in notification_targets:

        if not isinstance(target, dict):
            continue

        notification = _build_notification(
            target=target,
            decision=decision,
            policy_name=policy_name,
            effective_severity=effective_severity,
            risk_summary=risk_summary,
            evaluation_result=evaluation_result,
        )

        notifications.append(notification)

    # =================================================
    # COUNT ACTION-REQUIRED NOTIFICATIONS
    # =================================================

    action_required_count = sum(
        1 for n in notifications
        if n.get("requires_action")
    )

    manifest = {
        "notifications_triggered":      True,
        "notification_count":           len(notifications),
        "action_required_count":        action_required_count,
        "notifications":                notifications,
        "dispatch_status":              "pending",

        # NOTE:
        # dispatch_status transitions to "dispatched"
        # when the integration dispatcher confirms send.
        # This is a Phase 4 integration concern.
    }

    logger.info(
        "notification_manifest_built",
        extra={
            "extra": {
                "decision":                 decision,
                "policy_name":              policy_name,
                "notification_count":       len(notifications),
                "action_required_count":    action_required_count,
                "effective_severity":       effective_severity,
            }
        }
    )

    return manifest
