"""Core domain models for the cloudguard audit engine.

These are deliberately plain :mod:`dataclasses` (no third-party dependency) so
the engine runs on any stock Python 3.10+ interpreter.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    """Finding severity, ordered most-to-least serious.

    The numeric ``weight`` drives the posture score deduction.
    """

    CRITICAL = ("CRITICAL", 40)
    HIGH = ("HIGH", 20)
    MEDIUM = ("MEDIUM", 8)
    LOW = ("LOW", 3)
    INFO = ("INFO", 0)

    def __init__(self, label: str, weight: int) -> None:
        self.label = label
        self.weight = weight

    @property
    def rank(self) -> int:
        """Higher rank == more severe. Useful for sorting / thresholds."""
        order = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }
        return order[self.label]

    @classmethod
    def from_label(cls, label: str) -> Severity:
        for member in cls:
            if member.label == label.upper():
                return member
        raise ValueError(f"Unknown severity: {label!r}")


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security finding produced by a check.

    Attributes:
        check_id: Stable identifier of the originating check (e.g. ``IAM-001``).
        title: Short human-readable summary.
        severity: Impact rating.
        resource: The affected resource (ARN, name, id) or ``"account"``.
        cis_control: CIS AWS Foundations Benchmark control id, if applicable.
        description: What is wrong and why it matters.
        remediation: Concrete fix, ideally pointing at the Terraform module.
        evidence: Structured supporting data (the values that triggered it).
    """

    check_id: str
    title: str
    severity: Severity
    resource: str
    description: str
    remediation: str
    cis_control: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.label,
            "resource": self.resource,
            "cis_control": self.cis_control,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class CheckMeta:
    """Metadata describing a registered check."""

    check_id: str
    title: str
    category: str
    default_severity: Severity
    cis_control: str | None = None


@dataclass(frozen=True, slots=True)
class AuditResult:
    """Aggregated outcome of an audit run."""

    account_id: str
    findings: Sequence[Finding]
    checks_run: int

    @property
    def counts(self) -> dict[str, int]:
        """Number of findings per severity label (all severities present)."""
        result = {s.label: 0 for s in Severity}
        for finding in self.findings:
            result[finding.severity.label] += 1
        return result

    @property
    def score(self) -> int:
        """Posture score in ``[0, 100]``.

        Starts at 100 and deducts the severity weight of every finding, floored
        at zero. A hardened account with no findings scores 100.
        """
        deduction = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - deduction)

    @property
    def grade(self) -> str:
        """Letter grade derived from :attr:`score`."""
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def highest_severity(self) -> Severity:
        """The most severe finding present, or ``INFO`` when there are none."""
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def sorted_findings(self) -> list[Finding]:
        """Findings sorted most-severe first, then by check id."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.check_id, f.resource),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "checks_run": self.checks_run,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
