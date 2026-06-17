"""Human-friendly console report with optional ANSI colour.

No third-party dependency: colour is emitted with raw ANSI escape codes and can
be disabled (e.g. when output is redirected or ``NO_COLOR`` is set).
"""

from __future__ import annotations

import os
import sys

from cloudguard.models import AuditResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",  # white on red
    Severity.HIGH: "\033[1;31m",  # bright red
    Severity.MEDIUM: "\033[1;33m",  # yellow
    Severity.LOW: "\033[1;36m",  # cyan
    Severity.INFO: "\033[1;32m",  # green
}
_RESET = "\033[0m"


def _use_color(stream: object) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _paint(text: str, severity: Severity, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS[severity]}{text}{_RESET}"


def render_console(result: AuditResult, *, color: bool | None = None) -> str:
    """Render a console summary + findings table.

    Args:
        result: The audit result.
        color: Force colour on/off. ``None`` auto-detects from stdout.
    """
    enabled = _use_color(sys.stdout) if color is None else color
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"  CloudGuard Audit - account {result.account_id}")
    lines.append("=" * 72)
    lines.append(
        f"  Posture score: {result.score}/100  (grade {result.grade})"
        f"   checks run: {result.checks_run}"
    )
    lines.append("")
    lines.append("  Findings by severity:")
    counts = result.counts
    for severity in Severity:
        label = severity.label
        count = counts[label]
        marker = _paint(f"{label:>8}", severity, enabled)
        lines.append(f"    {marker} : {count}")
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append(_paint("  No findings — account is hardened. ", Severity.INFO, enabled))
        lines.append("=" * 72)
        return "\n".join(lines)

    lines.append("  Findings (most severe first):")
    lines.append("  " + "-" * 70)
    for finding in findings:
        tag = _paint(f"[{finding.severity.label}]", finding.severity, enabled)
        cis = f" CIS {finding.cis_control}" if finding.cis_control else ""
        lines.append(f"  {tag} {finding.check_id}{cis}  {finding.resource}")
        lines.append(f"      {finding.title}")
        lines.append(f"      fix: {finding.remediation}")
        lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines)
