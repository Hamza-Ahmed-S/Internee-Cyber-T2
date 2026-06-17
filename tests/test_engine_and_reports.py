"""End-to-end tests: engine aggregation, scoring, and report rendering."""

from __future__ import annotations

import json

from cloudguard.engine import run_audit
from cloudguard.report import render_console, render_json, render_markdown


def test_engine_runs_all_registered_checks(vulnerable_snapshot, sample_events) -> None:
    result = run_audit(vulnerable_snapshot, sample_events)
    # The vulnerable account should produce many findings and a poor grade.
    assert result.checks_run >= 18
    assert len(result.findings) > 10
    assert result.score < 50
    assert result.grade in {"D", "F"}
    assert result.highest_severity().label == "CRITICAL"


def test_engine_clean_account_passes(hardened_snapshot) -> None:
    # No events => no behavioural findings; hardened config => no config findings.
    result = run_audit(hardened_snapshot, [])
    assert result.findings == []
    assert result.score == 100
    assert result.grade == "A"


def test_engine_without_events(vulnerable_snapshot) -> None:
    result = run_audit(vulnerable_snapshot)
    # Behavioural checks contribute nothing without events.
    behavioural = [f for f in result.findings if f.check_id.startswith("CTA-")]
    assert behavioural == []


def test_json_report_is_valid_json(vulnerable_snapshot, sample_events) -> None:
    result = run_audit(vulnerable_snapshot, sample_events)
    payload = json.loads(render_json(result))
    assert payload["account_id"] == "123456789012"
    assert payload["score"] == result.score
    assert len(payload["findings"]) == len(result.findings)
    # Findings are sorted most-severe first.
    severities = [f["severity"] for f in payload["findings"]]
    assert severities[0] == "CRITICAL"


def test_markdown_report_contains_findings(vulnerable_snapshot, sample_events) -> None:
    result = run_audit(vulnerable_snapshot, sample_events)
    md = render_markdown(result, generated_at="2026-06-11 12:00 UTC")
    assert "# CloudGuard Security Audit Report" in md
    assert "CIS" in md
    assert "IAM-001" in md
    assert "2026-06-11 12:00 UTC" in md


def test_markdown_clean_account(hardened_snapshot) -> None:
    result = run_audit(hardened_snapshot, [])
    md = render_markdown(result)
    assert "No findings" in md


def test_console_report_no_color(vulnerable_snapshot, sample_events) -> None:
    result = run_audit(vulnerable_snapshot, sample_events)
    text = render_console(result, color=False)
    assert "\033[" not in text  # no ANSI codes when colour disabled
    assert "CloudGuard Audit" in text
    assert "Posture score" in text
