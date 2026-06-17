"""Tests for behavioural CloudTrail checks."""

from __future__ import annotations

from cloudguard.checks import AuditContext
from cloudguard.checks.cloudtrail_checks import (
    console_login_without_mfa,
    root_account_usage,
    sensitive_control_plane_changes,
    unauthorized_api_bursts,
)
from cloudguard.ingest import AccountSnapshot, CloudTrailEvent


def _ctx(snapshot: AccountSnapshot, events: list[CloudTrailEvent]) -> AuditContext:
    return AuditContext(snapshot=snapshot, events=tuple(events))


def test_root_usage_flagged(
    vulnerable_snapshot: AccountSnapshot,
    sample_events: list[CloudTrailEvent],
) -> None:
    findings = list(root_account_usage(_ctx(vulnerable_snapshot, sample_events)))
    assert len(findings) == 1
    assert findings[0].evidence["count"] == 2


def test_root_usage_clean_without_root_events(
    vulnerable_snapshot: AccountSnapshot,
    sample_events: list[CloudTrailEvent],
) -> None:
    non_root = [e for e in sample_events if not e.is_root]
    findings = list(root_account_usage(_ctx(vulnerable_snapshot, non_root)))
    assert findings == []


def test_console_login_without_mfa(
    vulnerable_snapshot: AccountSnapshot,
    sample_events: list[CloudTrailEvent],
) -> None:
    findings = list(console_login_without_mfa(_ctx(vulnerable_snapshot, sample_events)))
    # carol-ops (No) and the root ConsoleLogin (No); alice-admin used MFA.
    assert len(findings) == 2
    assert all(f.evidence["mfa_used"] is False for f in findings)


def test_unauthorized_burst(
    vulnerable_snapshot: AccountSnapshot,
    sample_events: list[CloudTrailEvent],
) -> None:
    findings = list(unauthorized_api_bursts(_ctx(vulnerable_snapshot, sample_events)))
    assert len(findings) == 1
    assert findings[0].evidence["unauthorized_calls"] == 5
    assert "bob-ci" in findings[0].resource


def test_sensitive_control_plane_changes(
    vulnerable_snapshot: AccountSnapshot,
    sample_events: list[CloudTrailEvent],
) -> None:
    findings = list(sensitive_control_plane_changes(_ctx(vulnerable_snapshot, sample_events)))
    names = {f.evidence["event_name"] for f in findings}
    assert "StopLogging" in names
    assert "AuthorizeSecurityGroupIngress" in names
