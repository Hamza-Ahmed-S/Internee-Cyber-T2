"""Tests for the domain models: severity ordering, scoring, grading."""

from __future__ import annotations

import pytest

from cloudguard.models import AuditResult, Finding, Severity


def _finding(severity: Severity, check_id: str = "X-001") -> Finding:
    return Finding(
        check_id=check_id,
        title="t",
        severity=severity,
        resource="r",
        description="d",
        remediation="fix",
    )


def test_severity_from_label_roundtrip() -> None:
    for member in Severity:
        assert Severity.from_label(member.label) is member
        assert Severity.from_label(member.label.lower()) is member


def test_severity_from_label_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        Severity.from_label("BOGUS")


def test_severity_rank_is_strictly_ordered() -> None:
    ranks = [s.rank for s in Severity]
    assert ranks == sorted(ranks, reverse=True)
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_score_is_100_with_no_findings() -> None:
    result = AuditResult(account_id="1", findings=[], checks_run=10)
    assert result.score == 100
    assert result.grade == "A"
    assert result.highest_severity() is Severity.INFO


def test_score_deducts_weights_and_floors_at_zero() -> None:
    findings = [_finding(Severity.CRITICAL, f"C-{i}") for i in range(5)]
    result = AuditResult(account_id="1", findings=findings, checks_run=5)
    # 5 * 40 = 200 deduction, floored to 0.
    assert result.score == 0
    assert result.grade == "F"


def test_counts_cover_all_severities() -> None:
    findings = [_finding(Severity.HIGH), _finding(Severity.LOW, "Y-1")]
    result = AuditResult(account_id="1", findings=findings, checks_run=2)
    counts = result.counts
    assert set(counts) == {s.label for s in Severity}
    assert counts["HIGH"] == 1
    assert counts["LOW"] == 1
    assert counts["CRITICAL"] == 0


def test_sorted_findings_most_severe_first() -> None:
    findings = [
        _finding(Severity.LOW, "A-1"),
        _finding(Severity.CRITICAL, "B-1"),
        _finding(Severity.MEDIUM, "C-1"),
    ]
    result = AuditResult(account_id="1", findings=findings, checks_run=3)
    severities = [f.severity for f in result.sorted_findings()]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_to_dict_shape() -> None:
    result = AuditResult(account_id="42", findings=[_finding(Severity.HIGH)], checks_run=1)
    data = result.to_dict()
    assert data["account_id"] == "42"
    assert data["grade"] == result.grade
    assert data["findings"][0]["severity"] == "HIGH"
