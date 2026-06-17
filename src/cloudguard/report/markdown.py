"""Human-readable Markdown report, suitable for committing as an audit record."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudguard.models import AuditResult, Severity


def _emoji(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "🟥",
        Severity.HIGH: "🟧",
        Severity.MEDIUM: "🟨",
        Severity.LOW: "🟦",
        Severity.INFO: "🟩",
    }[severity]


def render_markdown(result: AuditResult, *, generated_at: str | None = None) -> str:
    """Render the audit result as a Markdown document."""
    when = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = result.counts
    lines: list[str] = []
    lines.append("# CloudGuard Security Audit Report")
    lines.append("")
    lines.append(f"- **Account:** `{result.account_id}`")
    lines.append(f"- **Generated:** {when}")
    lines.append(f"- **Posture score:** {result.score}/100 (grade **{result.grade}**)")
    lines.append(f"- **Checks executed:** {result.checks_run}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for severity in Severity:
        lines.append(f"| {_emoji(severity)} {severity.label} | {counts[severity.label]} |")
    lines.append("")

    findings = result.sorted_findings()
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings — the account satisfies all checks. ✅")
        lines.append("")
        return "\n".join(lines)

    lines.append("| # | Severity | Check | CIS | Resource | Finding |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for index, finding in enumerate(findings, start=1):
        cis = finding.cis_control or "—"
        lines.append(
            f"| {index} | {_emoji(finding.severity)} {finding.severity.label} "
            f"| `{finding.check_id}` | {cis} | `{finding.resource}` | {finding.title} |"
        )
    lines.append("")

    lines.append("## Details & Remediation")
    lines.append("")
    for finding in findings:
        cis = f" · CIS {finding.cis_control}" if finding.cis_control else ""
        lines.append(f"### {_emoji(finding.severity)} `{finding.check_id}` — {finding.title}")
        lines.append("")
        lines.append(f"- **Severity:** {finding.severity.label}{cis}")
        lines.append(f"- **Resource:** `{finding.resource}`")
        lines.append(f"- **Description:** {finding.description}")
        lines.append(f"- **Remediation:** {finding.remediation}")
        if finding.evidence:
            evidence = ", ".join(f"`{k}={v}`" for k, v in finding.evidence.items())
            lines.append(f"- **Evidence:** {evidence}")
        lines.append("")
    return "\n".join(lines)
