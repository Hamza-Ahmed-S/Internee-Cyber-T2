"""Input loaders: turn raw JSON/JSONL into typed snapshot and event objects."""

from __future__ import annotations

from cloudguard.ingest.cloudtrail import CloudTrailEvent, load_cloudtrail_events
from cloudguard.ingest.snapshot import (
    AccessKey,
    AccountSnapshot,
    IamUser,
    ManagedPolicy,
    PasswordPolicy,
    RootAccount,
    S3Bucket,
    SecurityGroup,
    SecurityGroupRule,
    Trail,
    load_snapshot,
)

__all__ = [
    "AccessKey",
    "AccountSnapshot",
    "CloudTrailEvent",
    "IamUser",
    "ManagedPolicy",
    "PasswordPolicy",
    "RootAccount",
    "S3Bucket",
    "SecurityGroup",
    "SecurityGroupRule",
    "Trail",
    "load_cloudtrail_events",
    "load_snapshot",
]
