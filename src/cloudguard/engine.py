"""The audit engine: run every registered check and aggregate findings."""

from __future__ import annotations

from cloudguard.checks import AuditContext, registered_checks
from cloudguard.ingest import AccountSnapshot, CloudTrailEvent
from cloudguard.models import AuditResult, Finding


def run_audit(
    snapshot: AccountSnapshot,
    events: list[CloudTrailEvent] | None = None,
) -> AuditResult:
    """Execute all registered checks against the snapshot and events.

    Args:
        snapshot: The account configuration snapshot to audit.
        events: Optional CloudTrail events for behavioural checks. When omitted,
            activity checks simply produce no findings.

    Returns:
        An :class:`~cloudguard.models.AuditResult` with all findings, the number
        of checks executed, and a derived posture score/grade.
    """
    ctx = AuditContext(snapshot=snapshot, events=tuple(events or ()))
    findings: list[Finding] = []
    checks = registered_checks()
    for _meta, func in checks:
        findings.extend(func(ctx))
    return AuditResult(
        account_id=snapshot.account_id,
        findings=findings,
        checks_run=len(checks),
    )
