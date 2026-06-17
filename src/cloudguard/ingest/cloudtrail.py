"""Typed model of AWS CloudTrail events, plus a JSONL loader.

CloudTrail delivers events as JSON records. For offline analysis we read them
from a newline-delimited JSON (``.jsonl``) file where each line is one event in
the native CloudTrail schema (``eventTime``, ``eventName``, ``userIdentity`` …).
This matches the shape of records found in CloudTrail's S3 delivery and in many
AWS Open Data security log samples.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class CloudTrailError(ValueError):
    """Raised when a CloudTrail log file cannot be parsed."""


@dataclass(frozen=True, slots=True)
class CloudTrailEvent:
    """A single CloudTrail management/data event (subset of fields we use)."""

    event_time: str
    event_name: str
    event_source: str
    aws_region: str
    source_ip: str
    user_type: str
    user_arn: str
    mfa_used: bool
    error_code: str | None
    raw: Mapping[str, Any]

    @property
    def is_root(self) -> bool:
        return self.user_type == "Root"

    @property
    def failed(self) -> bool:
        return self.error_code is not None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CloudTrailEvent:
        identity = data.get("userIdentity", {}) or {}
        additional = data.get("additionalEventData", {}) or {}
        mfa_raw = additional.get("MFAUsed")
        mfa_used = str(mfa_raw).lower() in {"yes", "true", "1"}
        return cls(
            event_time=str(data.get("eventTime", "")),
            event_name=str(data.get("eventName", "")),
            event_source=str(data.get("eventSource", "")),
            aws_region=str(data.get("awsRegion", "")),
            source_ip=str(data.get("sourceIPAddress", "")),
            user_type=str(identity.get("type", "")),
            user_arn=str(identity.get("arn", "")),
            mfa_used=mfa_used,
            error_code=data.get("errorCode"),
            raw=dict(data),
        )


def _iter_records(raw: str) -> Iterator[Mapping[str, Any]]:
    """Yield event records from either JSONL or a ``{"Records": [...]}`` object."""
    stripped = raw.strip()
    if not stripped:
        return
    # Support the CloudTrail "Records" envelope as well as plain JSONL.
    if stripped[0] == "{" and '"Records"' in stripped[:200]:
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise CloudTrailError(f"invalid CloudTrail JSON: {exc}") from exc
        records = obj.get("Records", [])
        if not isinstance(records, list):
            raise CloudTrailError("'Records' must be a list")
        yield from records
        return
    for lineno, line in enumerate(stripped.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise CloudTrailError(f"invalid JSON on line {lineno}: {exc}") from exc


def load_cloudtrail_events(path: str | Path) -> list[CloudTrailEvent]:
    """Load CloudTrail events from a ``.jsonl`` file or a ``Records`` envelope."""
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CloudTrailError(f"cannot read CloudTrail file: {file_path}") from exc
    return [CloudTrailEvent.from_dict(rec) for rec in _iter_records(raw)]
