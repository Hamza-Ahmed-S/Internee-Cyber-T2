"""Tests for CIS-mapped configuration posture checks."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from cloudguard.checks import AuditContext
from cloudguard.checks.config_checks import (
    access_keys_rotated,
    console_users_have_mfa,
    ebs_default_encryption,
    multi_region_trail_logging,
    no_wildcard_admin_policy,
    no_world_open_admin_ports,
    password_policy_strength,
    root_mfa_enabled,
    root_no_access_keys,
    s3_encryption,
    s3_not_public,
    s3_versioning,
    trail_kms_encryption,
    trail_log_validation,
)
from cloudguard.ingest import AccountSnapshot
from cloudguard.models import Finding


def _ids(
    check: Callable[[AuditContext], Iterable[Finding]],
    snapshot: AccountSnapshot,
) -> list[str]:
    ctx = AuditContext(snapshot=snapshot)
    return [f.check_id for f in check(ctx)]


def test_root_mfa_flagged_when_disabled(vulnerable_snapshot: AccountSnapshot) -> None:
    assert _ids(root_mfa_enabled, vulnerable_snapshot) == ["IAM-001"]


def test_root_mfa_clean_when_enabled(hardened_snapshot: AccountSnapshot) -> None:
    assert _ids(root_mfa_enabled, hardened_snapshot) == []


def test_root_access_keys_flagged(vulnerable_snapshot: AccountSnapshot) -> None:
    assert _ids(root_no_access_keys, vulnerable_snapshot) == ["IAM-002"]
    # severity is CRITICAL
    ctx = AuditContext(snapshot=vulnerable_snapshot)
    finding = next(iter(root_no_access_keys(ctx)))
    assert finding.severity.label == "CRITICAL"


def test_console_users_without_mfa(vulnerable_snapshot: AccountSnapshot) -> None:
    ctx = AuditContext(snapshot=vulnerable_snapshot)
    findings = list(console_users_have_mfa(ctx))
    # carol-ops has console access without MFA; alice-admin has MFA.
    assert len(findings) == 1
    assert "carol-ops" in findings[0].resource


def test_stale_access_key_flagged(vulnerable_snapshot: AccountSnapshot) -> None:
    ctx = AuditContext(snapshot=vulnerable_snapshot)
    findings = list(access_keys_rotated(ctx))
    assert len(findings) == 1
    assert "bob-ci" in findings[0].resource


def test_weak_password_policy(vulnerable_snapshot: AccountSnapshot) -> None:
    assert _ids(password_policy_strength, vulnerable_snapshot) == ["IAM-005"]


def test_strong_password_policy_clean(hardened_snapshot: AccountSnapshot) -> None:
    assert _ids(password_policy_strength, hardened_snapshot) == []


def test_wildcard_admin_policy_flagged(vulnerable_snapshot: AccountSnapshot) -> None:
    ctx = AuditContext(snapshot=vulnerable_snapshot)
    findings = list(no_wildcard_admin_policy(ctx))
    assert len(findings) == 1
    assert "legacy-full-access" in findings[0].title


def test_multi_region_trail_present_is_clean(vulnerable_snapshot: AccountSnapshot) -> None:
    # The sample has an active multi-region trail, so this check is satisfied.
    assert _ids(multi_region_trail_logging, vulnerable_snapshot) == []


def test_trail_validation_and_kms_flagged(vulnerable_snapshot: AccountSnapshot) -> None:
    assert _ids(trail_log_validation, vulnerable_snapshot) == ["CT-002"]
    assert _ids(trail_kms_encryption, vulnerable_snapshot) == ["CT-003"]


def test_public_bucket_is_critical(vulnerable_snapshot: AccountSnapshot) -> None:
    ctx = AuditContext(snapshot=vulnerable_snapshot)
    findings = list(s3_not_public(ctx))
    assert len(findings) == 1
    assert findings[0].severity.label == "CRITICAL"
    assert "internee-public-website" in findings[0].resource


def test_s3_encryption_and_versioning(vulnerable_snapshot: AccountSnapshot) -> None:
    ctx = AuditContext(snapshot=vulnerable_snapshot)
    enc = list(s3_encryption(ctx))
    ver = list(s3_versioning(ctx))
    assert len(enc) == 1  # only user-uploads lacks encryption
    assert len(ver) == 2  # website + user-uploads lack versioning


def test_world_open_admin_ports(vulnerable_snapshot: AccountSnapshot) -> None:
    ctx = AuditContext(snapshot=vulnerable_snapshot)
    findings = list(no_world_open_admin_ports(ctx))
    ports = {f.evidence["port"] for f in findings}
    assert ports == {22, 3389}


def test_ebs_default_encryption(
    vulnerable_snapshot: AccountSnapshot,
    hardened_snapshot: AccountSnapshot,
) -> None:
    assert _ids(ebs_default_encryption, vulnerable_snapshot) == ["EC2-002"]
    assert _ids(ebs_default_encryption, hardened_snapshot) == []
