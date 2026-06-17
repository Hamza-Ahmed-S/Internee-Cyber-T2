"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudguard.ingest import (
    AccountSnapshot,
    CloudTrailEvent,
    load_cloudtrail_events,
    load_snapshot,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "sample"


@pytest.fixture
def vulnerable_snapshot() -> AccountSnapshot:
    return load_snapshot(DATA_DIR / "account_snapshot.json")


@pytest.fixture
def hardened_snapshot() -> AccountSnapshot:
    return load_snapshot(DATA_DIR / "hardened_account_snapshot.json")


@pytest.fixture
def sample_events() -> list[CloudTrailEvent]:
    return load_cloudtrail_events(DATA_DIR / "cloudtrail_events.jsonl")
