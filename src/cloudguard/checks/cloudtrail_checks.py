"""Behavioural checks over CloudTrail events.

Where :mod:`config_checks` reasons about *static* configuration, these checks
reason about *activity*: what actually happened in the account. They map to the
CIS "monitoring" controls (section 4) and to common detection use-cases.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from cloudguard.checks.base import AuditContext, check
from cloudguard.models import Finding, Severity

# Threshold of AccessDenied/Unauthorized errors from one principal before we
# treat it as suspicious enumeration/abuse rather than a one-off mistake.
_UNAUTHORIZED_BURST_THRESHOLD = 5

# Sensitive control-plane events worth flagging when they occur (change
# monitoring). Mapped loosely to CIS 4.x metric-filter recommendations.
_SENSITIVE_EVENTS = {
    "DeleteTrail": ("CloudTrail logging configuration changed", "4.5"),
    "StopLogging": ("CloudTrail logging was stopped", "4.5"),
    "UpdateTrail": ("CloudTrail logging configuration changed", "4.5"),
    "PutUserPolicy": ("IAM policy changed", "4.4"),
    "AttachUserPolicy": ("IAM policy changed", "4.4"),
    "PutGroupPolicy": ("IAM policy changed", "4.4"),
    "AuthorizeSecurityGroupIngress": ("Security group ingress changed", "4.10"),
    "DisableKey": ("KMS key scheduled for deletion/disabled", "4.7"),
    "ScheduleKeyDeletion": ("KMS key scheduled for deletion/disabled", "4.7"),
}


@check(
    check_id="CTA-001",
    title="No root account activity",
    category="Activity",
    default_severity=Severity.HIGH,
    cis_control="4.3",
)
def root_account_usage(ctx: AuditContext) -> Iterator[Finding]:
    root_events = [e for e in ctx.events if e.is_root]
    if root_events:
        sample = root_events[0]
        yield Finding(
            check_id="CTA-001",
            title=f"Root account used {len(root_events)} time(s)",
            severity=Severity.HIGH,
            resource="account:root",
            cis_control="4.3",
            description=(
                "The root user performed API actions. Root should be reserved for "
                "the few tasks that strictly require it and otherwise unused."
            ),
            remediation="Investigate root usage; operate via least-privilege roles.",
            evidence={
                "count": len(root_events),
                "first_event": sample.event_name,
                "first_time": sample.event_time,
                "source_ip": sample.source_ip,
            },
        )


@check(
    check_id="CTA-002",
    title="No console sign-in without MFA",
    category="Activity",
    default_severity=Severity.HIGH,
    cis_control="4.2",
)
def console_login_without_mfa(ctx: AuditContext) -> Iterator[Finding]:
    for event in ctx.events:
        if event.event_name != "ConsoleLogin" or event.failed:
            continue
        if not event.mfa_used:
            yield Finding(
                check_id="CTA-002",
                title=f"Console sign-in without MFA by {event.user_arn or 'unknown'}",
                severity=Severity.HIGH,
                resource=event.user_arn or "iam:unknown",
                cis_control="4.2",
                description="A successful console sign-in did not use MFA.",
                remediation="Enforce MFA for all console users.",
                evidence={
                    "source_ip": event.source_ip,
                    "time": event.event_time,
                    "mfa_used": False,
                },
            )


@check(
    check_id="CTA-003",
    title="No bursts of unauthorized API calls",
    category="Activity",
    default_severity=Severity.MEDIUM,
    cis_control="4.1",
)
def unauthorized_api_bursts(ctx: AuditContext) -> Iterator[Finding]:
    per_principal: dict[str, int] = defaultdict(int)
    for event in ctx.events:
        if event.error_code in {"AccessDenied", "UnauthorizedOperation"}:
            per_principal[event.user_arn or event.source_ip] += 1
    for principal, count in sorted(per_principal.items()):
        if count >= _UNAUTHORIZED_BURST_THRESHOLD:
            yield Finding(
                check_id="CTA-003",
                title=f"{count} unauthorized API calls from {principal}",
                severity=Severity.MEDIUM,
                resource=principal,
                cis_control="4.1",
                description=(
                    "A burst of AccessDenied/Unauthorized errors can indicate "
                    "credential misuse or permission enumeration."
                ),
                remediation="Investigate the principal; rotate credentials if abused.",
                evidence={"unauthorized_calls": count},
            )


@check(
    check_id="CTA-004",
    title="Sensitive control-plane changes are reviewed",
    category="Activity",
    default_severity=Severity.MEDIUM,
    cis_control="4.4",
)
def sensitive_control_plane_changes(ctx: AuditContext) -> Iterator[Finding]:
    for event in ctx.events:
        if event.failed:
            continue
        mapping = _SENSITIVE_EVENTS.get(event.event_name)
        if mapping is None:
            continue
        title, cis = mapping
        yield Finding(
            check_id="CTA-004",
            title=f"{title} ({event.event_name})",
            severity=Severity.MEDIUM,
            resource=event.user_arn or event.event_source,
            cis_control=cis,
            description=(
                "A security-sensitive control-plane action was performed and "
                "should be confirmed as authorised."
            ),
            remediation="Confirm the change was expected; alert on these events.",
            evidence={
                "event_name": event.event_name,
                "time": event.event_time,
                "source_ip": event.source_ip,
                "region": event.aws_region,
            },
        )
