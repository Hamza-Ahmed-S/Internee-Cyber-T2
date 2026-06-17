"""Tests for the snapshot and CloudTrail loaders, including error handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudguard.ingest import load_cloudtrail_events, load_snapshot
from cloudguard.ingest.cloudtrail import CloudTrailError, CloudTrailEvent
from cloudguard.ingest.snapshot import AccountSnapshot, SnapshotError


def test_load_snapshot_parses_sample(vulnerable_snapshot: AccountSnapshot) -> None:
    snap = vulnerable_snapshot
    assert snap.account_id == "123456789012"
    assert snap.root_account.mfa_enabled is False
    assert len(snap.iam_users) == 3
    assert any(b.is_public for b in snap.s3_buckets)


def test_load_snapshot_missing_file_raises() -> None:
    with pytest.raises(SnapshotError):
        load_snapshot("does-not-exist.json")


def test_load_snapshot_invalid_json_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SnapshotError):
        load_snapshot(bad)


def test_load_snapshot_non_object_raises(tmp_path: Path) -> None:
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(SnapshotError):
        load_snapshot(bad)


def test_load_snapshot_missing_account_id_raises(tmp_path: Path) -> None:
    bad = tmp_path / "no-id.json"
    bad.write_text("{}", encoding="utf-8")
    with pytest.raises(SnapshotError):
        load_snapshot(bad)


def test_load_cloudtrail_jsonl(sample_events: list[CloudTrailEvent]) -> None:
    assert len(sample_events) == 11
    root = [e for e in sample_events if e.is_root]
    assert len(root) == 2
    login = next(e for e in sample_events if e.event_name == "ConsoleLogin")
    assert login.mfa_used is False


def test_load_cloudtrail_records_envelope(tmp_path: Path) -> None:
    envelope = tmp_path / "ct.json"
    envelope.write_text(
        '{"Records": [{"eventName": "X", "userIdentity": {"type": "Root"}}]}',
        encoding="utf-8",
    )
    events = load_cloudtrail_events(envelope)
    assert len(events) == 1
    assert events[0].is_root


def test_load_cloudtrail_invalid_line_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"ok": 1}\n{nope}\n', encoding="utf-8")
    with pytest.raises(CloudTrailError):
        load_cloudtrail_events(bad)


def test_load_cloudtrail_empty_file_is_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\n", encoding="utf-8")
    assert load_cloudtrail_events(empty) == []
