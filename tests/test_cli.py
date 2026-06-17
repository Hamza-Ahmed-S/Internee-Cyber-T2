"""Tests for the command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudguard.cli import main

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "sample"
SNAPSHOT = DATA_DIR / "account_snapshot.json"
HARDENED = DATA_DIR / "hardened_account_snapshot.json"
EVENTS = DATA_DIR / "cloudtrail_events.jsonl"


def test_cli_console_output(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["audit", "--snapshot", str(SNAPSHOT), "--format", "console"])
    out = capsys.readouterr().out
    assert code == 0
    assert "CloudGuard Audit" in out


def test_cli_json_to_file(tmp_path: Path) -> None:
    out_file = tmp_path / "report.json"
    code = main(
        [
            "audit",
            "--snapshot",
            str(SNAPSHOT),
            "--cloudtrail",
            str(EVENTS),
            "--format",
            "json",
            "--output",
            str(out_file),
        ]
    )
    assert code == 0
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["account_id"] == "123456789012"


def test_cli_fail_on_high_returns_nonzero() -> None:
    code = main(
        [
            "audit",
            "--snapshot",
            str(SNAPSHOT),
            "--cloudtrail",
            str(EVENTS),
            "--format",
            "json",
            "--fail-on",
            "HIGH",
        ]
    )
    assert code == 2


def test_cli_fail_on_clean_account_returns_zero() -> None:
    code = main(
        ["audit", "--snapshot", str(HARDENED), "--format", "json", "--fail-on", "LOW"]
    )
    assert code == 0


def test_cli_bad_snapshot_returns_one(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["audit", "--snapshot", "nope.json"])
    err = capsys.readouterr().err
    assert code == 1
    assert "error" in err.lower()
