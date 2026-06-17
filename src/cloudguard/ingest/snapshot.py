"""Typed model of an AWS account configuration snapshot, plus its JSON loader.

A *snapshot* is the point-in-time security-relevant configuration of an account:
the inputs that the CIS-style posture checks reason over. In a live deployment
this would be assembled from IAM, S3, EC2 and CloudTrail describe/get API calls;
here it is read from a committed JSON file so the engine runs offline.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SnapshotError(ValueError):
    """Raised when a snapshot file is malformed or missing required fields."""


@dataclass(frozen=True, slots=True)
class AccessKey:
    active: bool
    last_rotated_days: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AccessKey:
        return cls(
            active=bool(data.get("active", False)),
            last_rotated_days=int(data.get("last_rotated_days", 0)),
        )


@dataclass(frozen=True, slots=True)
class IamUser:
    name: str
    console_access: bool
    mfa_enabled: bool
    access_keys: tuple[AccessKey, ...]
    attached_policy_arns: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IamUser:
        return cls(
            name=str(data["name"]),
            console_access=bool(data.get("console_access", False)),
            mfa_enabled=bool(data.get("mfa_enabled", False)),
            access_keys=tuple(AccessKey.from_dict(k) for k in data.get("access_keys", [])),
            attached_policy_arns=tuple(data.get("attached_policy_arns", [])),
        )


@dataclass(frozen=True, slots=True)
class ManagedPolicy:
    name: str
    arn: str
    document: Mapping[str, Any]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ManagedPolicy:
        return cls(
            name=str(data["name"]),
            arn=str(data.get("arn", "")),
            document=dict(data.get("document", {})),
        )


@dataclass(frozen=True, slots=True)
class Trail:
    name: str
    is_multi_region: bool
    is_logging: bool
    log_file_validation: bool
    kms_key_id: str | None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Trail:
        return cls(
            name=str(data["name"]),
            is_multi_region=bool(data.get("is_multi_region", False)),
            is_logging=bool(data.get("is_logging", False)),
            log_file_validation=bool(data.get("log_file_validation", False)),
            kms_key_id=data.get("kms_key_id"),
        )


@dataclass(frozen=True, slots=True)
class S3Bucket:
    name: str
    region: str
    is_public: bool
    public_access_block: bool
    encryption: str | None
    versioning: bool

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> S3Bucket:
        return cls(
            name=str(data["name"]),
            region=str(data.get("region", "us-east-1")),
            is_public=bool(data.get("is_public", False)),
            public_access_block=bool(data.get("public_access_block", False)),
            encryption=data.get("encryption"),
            versioning=bool(data.get("versioning", False)),
        )


@dataclass(frozen=True, slots=True)
class SecurityGroupRule:
    protocol: str
    from_port: int
    to_port: int
    cidr: str

    def covers_port(self, port: int) -> bool:
        return self.from_port <= port <= self.to_port

    @property
    def is_open_to_world(self) -> bool:
        return self.cidr in {"0.0.0.0/0", "::/0"}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SecurityGroupRule:
        return cls(
            protocol=str(data.get("protocol", "tcp")),
            from_port=int(data.get("from_port", 0)),
            to_port=int(data.get("to_port", 0)),
            cidr=str(data.get("cidr", "")),
        )


@dataclass(frozen=True, slots=True)
class SecurityGroup:
    group_id: str
    name: str
    ingress: tuple[SecurityGroupRule, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SecurityGroup:
        return cls(
            group_id=str(data["group_id"]),
            name=str(data.get("name", "")),
            ingress=tuple(SecurityGroupRule.from_dict(r) for r in data.get("ingress", [])),
        )


@dataclass(frozen=True, slots=True)
class RootAccount:
    mfa_enabled: bool
    hardware_mfa: bool
    active_access_keys: int

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RootAccount:
        return cls(
            mfa_enabled=bool(data.get("mfa_enabled", False)),
            hardware_mfa=bool(data.get("hardware_mfa", False)),
            active_access_keys=int(data.get("active_access_keys", 0)),
        )


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    minimum_length: int
    require_symbols: bool
    require_numbers: bool
    require_uppercase: bool
    require_lowercase: bool
    max_age_days: int | None
    reuse_prevention: int | None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PasswordPolicy:
        return cls(
            minimum_length=int(data.get("minimum_length", 0)),
            require_symbols=bool(data.get("require_symbols", False)),
            require_numbers=bool(data.get("require_numbers", False)),
            require_uppercase=bool(data.get("require_uppercase", False)),
            require_lowercase=bool(data.get("require_lowercase", False)),
            max_age_days=data.get("max_age_days"),
            reuse_prevention=data.get("reuse_prevention"),
        )


@dataclass(frozen=True, slots=True)
class AccountSnapshot:
    """The full security-relevant configuration of an AWS account."""

    account_id: str
    generated_at: str
    root_account: RootAccount
    password_policy: PasswordPolicy | None
    iam_users: tuple[IamUser, ...]
    managed_policies: tuple[ManagedPolicy, ...]
    trails: tuple[Trail, ...]
    s3_buckets: tuple[S3Bucket, ...]
    security_groups: tuple[SecurityGroup, ...]
    ebs_encryption_by_default: bool
    regions: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AccountSnapshot:
        try:
            account_id = str(data["account_id"])
        except KeyError as exc:  # pragma: no cover - defensive
            raise SnapshotError("snapshot is missing required 'account_id'") from exc

        policy_raw = data.get("password_policy")
        return cls(
            account_id=account_id,
            generated_at=str(data.get("generated_at", "")),
            root_account=RootAccount.from_dict(data.get("root_account", {})),
            password_policy=(PasswordPolicy.from_dict(policy_raw) if policy_raw else None),
            iam_users=tuple(IamUser.from_dict(u) for u in data.get("iam_users", [])),
            managed_policies=tuple(
                ManagedPolicy.from_dict(p) for p in data.get("managed_policies", [])
            ),
            trails=tuple(Trail.from_dict(t) for t in data.get("trails", [])),
            s3_buckets=tuple(S3Bucket.from_dict(b) for b in data.get("s3_buckets", [])),
            security_groups=tuple(
                SecurityGroup.from_dict(g) for g in data.get("security_groups", [])
            ),
            ebs_encryption_by_default=bool(data.get("ebs_encryption_by_default", False)),
            regions=tuple(data.get("regions", [])),
        )


def load_snapshot(path: str | Path) -> AccountSnapshot:
    """Load and parse an account snapshot from a JSON file."""
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SnapshotError(f"cannot read snapshot file: {file_path}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"snapshot is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SnapshotError("snapshot root must be a JSON object")
    return AccountSnapshot.from_dict(data)
