"""Configuration posture checks mapped to the CIS AWS Foundations Benchmark.

Each function inspects the :class:`~cloudguard.ingest.AccountSnapshot` and yields
findings for any control that is not satisfied. The CIS control id is recorded
on every finding so the report can present a traceable compliance mapping.
"""

from __future__ import annotations

from collections.abc import Iterator

from cloudguard.checks.base import AuditContext, check
from cloudguard.models import Finding, Severity

# Ports that must never be open to the whole internet.
_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}
# CIS 1.14 recommends rotating access keys at least every 90 days.
_KEY_ROTATION_MAX_DAYS = 90
# CIS 1.8 recommends a minimum password length of 14.
_MIN_PASSWORD_LENGTH = 14


@check(
    check_id="IAM-001",
    title="Root account MFA enabled",
    category="IAM",
    default_severity=Severity.CRITICAL,
    cis_control="1.5",
)
def root_mfa_enabled(ctx: AuditContext) -> Iterator[Finding]:
    root = ctx.snapshot.root_account
    if not root.mfa_enabled:
        yield Finding(
            check_id="IAM-001",
            title="Root account does not have MFA enabled",
            severity=Severity.CRITICAL,
            resource="account:root",
            cis_control="1.5",
            description=(
                "The root user has unrestricted access to the account. Without "
                "MFA, a leaked root password fully compromises the account."
            ),
            remediation=(
                "Enable a hardware or virtual MFA device on the root user. See "
                "terraform/modules/iam (account hardening guidance)."
            ),
            evidence={"mfa_enabled": root.mfa_enabled},
        )


@check(
    check_id="IAM-002",
    title="No active access keys on the root account",
    category="IAM",
    default_severity=Severity.CRITICAL,
    cis_control="1.4",
)
def root_no_access_keys(ctx: AuditContext) -> Iterator[Finding]:
    root = ctx.snapshot.root_account
    if root.active_access_keys > 0:
        yield Finding(
            check_id="IAM-002",
            title="Root account has active access keys",
            severity=Severity.CRITICAL,
            resource="account:root",
            cis_control="1.4",
            description=(
                "Programmatic root credentials are long-lived and grant full "
                "control. They should never exist."
            ),
            remediation="Delete all root access keys; use IAM roles instead.",
            evidence={"active_access_keys": root.active_access_keys},
        )


@check(
    check_id="IAM-003",
    title="Console users have MFA enabled",
    category="IAM",
    default_severity=Severity.HIGH,
    cis_control="1.10",
)
def console_users_have_mfa(ctx: AuditContext) -> Iterator[Finding]:
    for user in ctx.snapshot.iam_users:
        if user.console_access and not user.mfa_enabled:
            yield Finding(
                check_id="IAM-003",
                title=f"IAM user '{user.name}' has console access without MFA",
                severity=Severity.HIGH,
                resource=f"iam:user/{user.name}",
                cis_control="1.10",
                description=(
                    "Console users without MFA are vulnerable to password "
                    "phishing and reuse attacks."
                ),
                remediation="Enforce MFA via the IAM policy in terraform/modules/iam.",
                evidence={"console_access": True, "mfa_enabled": False},
            )


@check(
    check_id="IAM-004",
    title="Access keys rotated within 90 days",
    category="IAM",
    default_severity=Severity.MEDIUM,
    cis_control="1.14",
)
def access_keys_rotated(ctx: AuditContext) -> Iterator[Finding]:
    for user in ctx.snapshot.iam_users:
        for index, key in enumerate(user.access_keys):
            if key.active and key.last_rotated_days > _KEY_ROTATION_MAX_DAYS:
                yield Finding(
                    check_id="IAM-004",
                    title=f"Stale access key for IAM user '{user.name}'",
                    severity=Severity.MEDIUM,
                    resource=f"iam:user/{user.name}#key{index}",
                    cis_control="1.14",
                    description=(
                        "Access keys older than 90 days increase the window of "
                        "exposure if a key is leaked."
                    ),
                    remediation="Rotate the access key and automate rotation.",
                    evidence={"last_rotated_days": key.last_rotated_days},
                )


@check(
    check_id="IAM-005",
    title="Strong account password policy",
    category="IAM",
    default_severity=Severity.MEDIUM,
    cis_control="1.8",
)
def password_policy_strength(ctx: AuditContext) -> Iterator[Finding]:
    policy = ctx.snapshot.password_policy
    if policy is None:
        yield Finding(
            check_id="IAM-005",
            title="No IAM account password policy is configured",
            severity=Severity.HIGH,
            resource="account:password-policy",
            cis_control="1.8",
            description="Without a password policy, weak passwords are allowed.",
            remediation="Apply the password policy in terraform/modules/iam.",
            evidence={"password_policy": None},
        )
        return

    weaknesses: list[str] = []
    if policy.minimum_length < _MIN_PASSWORD_LENGTH:
        weaknesses.append(f"minimum_length={policy.minimum_length} (<14)")
    if not policy.require_symbols:
        weaknesses.append("symbols not required")
    if not policy.require_numbers:
        weaknesses.append("numbers not required")
    if not (policy.require_uppercase and policy.require_lowercase):
        weaknesses.append("mixed case not required")
    if weaknesses:
        yield Finding(
            check_id="IAM-005",
            title="IAM password policy is weak",
            severity=Severity.MEDIUM,
            resource="account:password-policy",
            cis_control="1.8",
            description="; ".join(weaknesses),
            remediation="Strengthen the password policy in terraform/modules/iam.",
            evidence={"weaknesses": weaknesses},
        )


@check(
    check_id="IAM-006",
    title="No customer-managed policy grants full admin (*:*)",
    category="IAM",
    default_severity=Severity.HIGH,
    cis_control="1.16",
)
def no_wildcard_admin_policy(ctx: AuditContext) -> Iterator[Finding]:
    for policy in ctx.snapshot.managed_policies:
        statements = policy.document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            actions = [actions] if isinstance(actions, str) else list(actions)
            resources = [resources] if isinstance(resources, str) else list(resources)
            if "*" in actions and "*" in resources:
                yield Finding(
                    check_id="IAM-006",
                    title=f"Customer-managed policy '{policy.name}' grants *:*",
                    severity=Severity.HIGH,
                    resource=policy.arn or f"iam:policy/{policy.name}",
                    cis_control="1.16",
                    description=(
                        "A policy allowing all actions on all resources violates "
                        "least privilege and is equivalent to administrator."
                    ),
                    remediation=(
                        "Scope the policy to required actions/resources. See the "
                        "least-privilege roles in terraform/modules/iam."
                    ),
                    evidence={"action": actions, "resource": resources},
                )
                break  # one finding per policy is enough


@check(
    check_id="CT-001",
    title="A multi-region CloudTrail trail is logging",
    category="Logging",
    default_severity=Severity.HIGH,
    cis_control="3.1",
)
def multi_region_trail_logging(ctx: AuditContext) -> Iterator[Finding]:
    has_active_multiregion = any(
        t.is_multi_region and t.is_logging for t in ctx.snapshot.trails
    )
    if not has_active_multiregion:
        yield Finding(
            check_id="CT-001",
            title="No active multi-region CloudTrail trail",
            severity=Severity.HIGH,
            resource="cloudtrail",
            cis_control="3.1",
            description=(
                "Without a multi-region trail that is actively logging, API "
                "activity in some regions is not recorded, blinding detection."
            ),
            remediation="Enable a multi-region trail with logging turned on.",
            evidence={"trail_count": len(ctx.snapshot.trails)},
        )


@check(
    check_id="CT-002",
    title="CloudTrail log file validation enabled",
    category="Logging",
    default_severity=Severity.MEDIUM,
    cis_control="3.2",
)
def trail_log_validation(ctx: AuditContext) -> Iterator[Finding]:
    for trail in ctx.snapshot.trails:
        if not trail.log_file_validation:
            yield Finding(
                check_id="CT-002",
                title=f"Trail '{trail.name}' has log file validation disabled",
                severity=Severity.MEDIUM,
                resource=f"cloudtrail:trail/{trail.name}",
                cis_control="3.2",
                description=(
                    "Log file validation lets you detect tampering with delivered "
                    "log files."
                ),
                remediation="Enable log file validation on the trail.",
                evidence={"log_file_validation": False},
            )


@check(
    check_id="CT-003",
    title="CloudTrail logs encrypted with KMS",
    category="Logging",
    default_severity=Severity.MEDIUM,
    cis_control="3.7",
)
def trail_kms_encryption(ctx: AuditContext) -> Iterator[Finding]:
    for trail in ctx.snapshot.trails:
        if not trail.kms_key_id:
            yield Finding(
                check_id="CT-003",
                title=f"Trail '{trail.name}' logs are not KMS-encrypted",
                severity=Severity.MEDIUM,
                resource=f"cloudtrail:trail/{trail.name}",
                cis_control="3.7",
                description="CloudTrail logs should be encrypted at rest with KMS.",
                remediation="Configure a KMS key for the trail (SSE-KMS).",
                evidence={"kms_key_id": None},
            )


@check(
    check_id="S3-001",
    title="No publicly accessible S3 buckets",
    category="S3",
    default_severity=Severity.CRITICAL,
    cis_control="2.1.5",
)
def s3_not_public(ctx: AuditContext) -> Iterator[Finding]:
    for bucket in ctx.snapshot.s3_buckets:
        if bucket.is_public or not bucket.public_access_block:
            severity = Severity.CRITICAL if bucket.is_public else Severity.MEDIUM
            yield Finding(
                check_id="S3-001",
                title=f"S3 bucket '{bucket.name}' is publicly exposed",
                severity=severity,
                resource=f"s3:bucket/{bucket.name}",
                cis_control="2.1.5",
                description=(
                    "Public buckets risk data exposure. Public Access Block must "
                    "be enabled and no public ACL/policy should be present."
                ),
                remediation="Enable S3 Block Public Access at the bucket/account level.",
                evidence={
                    "is_public": bucket.is_public,
                    "public_access_block": bucket.public_access_block,
                },
            )


@check(
    check_id="S3-002",
    title="S3 buckets encrypted at rest",
    category="S3",
    default_severity=Severity.MEDIUM,
    cis_control="2.1.1",
)
def s3_encryption(ctx: AuditContext) -> Iterator[Finding]:
    for bucket in ctx.snapshot.s3_buckets:
        if not bucket.encryption:
            yield Finding(
                check_id="S3-002",
                title=f"S3 bucket '{bucket.name}' has no default encryption",
                severity=Severity.MEDIUM,
                resource=f"s3:bucket/{bucket.name}",
                cis_control="2.1.1",
                description="Default encryption (SSE-S3 or SSE-KMS) is not enabled.",
                remediation="Enable default encryption (prefer SSE-KMS).",
                evidence={"encryption": bucket.encryption},
            )


@check(
    check_id="S3-003",
    title="S3 buckets have versioning enabled",
    category="S3",
    default_severity=Severity.LOW,
    cis_control="2.1.3",
)
def s3_versioning(ctx: AuditContext) -> Iterator[Finding]:
    for bucket in ctx.snapshot.s3_buckets:
        if not bucket.versioning:
            yield Finding(
                check_id="S3-003",
                title=f"S3 bucket '{bucket.name}' has versioning disabled",
                severity=Severity.LOW,
                resource=f"s3:bucket/{bucket.name}",
                cis_control="2.1.3",
                description=(
                    "Versioning protects against accidental deletion/overwrite "
                    "and is required for cross-region replication (data redundancy)."
                ),
                remediation=(
                    "Enable versioning; see the replicated buckets in "
                    "terraform/modules/backup."
                ),
                evidence={"versioning": False},
            )


@check(
    check_id="EC2-001",
    title="No security group opens SSH/RDP to the world",
    category="Network",
    default_severity=Severity.HIGH,
    cis_control="5.2",
)
def no_world_open_admin_ports(ctx: AuditContext) -> Iterator[Finding]:
    for group in ctx.snapshot.security_groups:
        for rule in group.ingress:
            if not rule.is_open_to_world:
                continue
            for port, label in _SENSITIVE_PORTS.items():
                if rule.covers_port(port):
                    yield Finding(
                        check_id="EC2-001",
                        title=(
                            f"Security group '{group.group_id}' allows {label} "
                            f"from 0.0.0.0/0"
                        ),
                        severity=Severity.HIGH,
                        resource=f"ec2:security-group/{group.group_id}",
                        cis_control="5.2",
                        description=(
                            f"Port {port} ({label}) is open to the entire internet, "
                            "exposing the host to brute-force and exploitation."
                        ),
                        remediation="Restrict ingress to known CIDRs or use SSM/VPN.",
                        evidence={
                            "port": port,
                            "cidr": rule.cidr,
                            "protocol": rule.protocol,
                        },
                    )


@check(
    check_id="EC2-002",
    title="EBS encryption by default enabled",
    category="Network",
    default_severity=Severity.MEDIUM,
    cis_control="2.2.1",
)
def ebs_default_encryption(ctx: AuditContext) -> Iterator[Finding]:
    if not ctx.snapshot.ebs_encryption_by_default:
        yield Finding(
            check_id="EC2-002",
            title="EBS encryption by default is disabled",
            severity=Severity.MEDIUM,
            resource="ec2:ebs-encryption",
            cis_control="2.2.1",
            description="New EBS volumes may be created unencrypted.",
            remediation="Enable EBS encryption by default in every region.",
            evidence={"ebs_encryption_by_default": False},
        )
