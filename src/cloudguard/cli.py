"""Command-line interface for the cloudguard audit engine.

Usage::

    cloudguard audit --snapshot data/sample/account_snapshot.json \\
        --cloudtrail data/sample/cloudtrail_events.jsonl \\
        --format markdown --output docs/REPORT.md --fail-on HIGH
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from cloudguard import __version__
from cloudguard.engine import run_audit
from cloudguard.ingest import load_cloudtrail_events, load_snapshot
from cloudguard.ingest.cloudtrail import CloudTrailError
from cloudguard.ingest.snapshot import SnapshotError
from cloudguard.models import AuditResult, Severity
from cloudguard.report import render_console, render_json, render_markdown

_RENDERERS = {
    "console": render_console,
    "json": render_json,
    "markdown": render_markdown,
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="Audit an AWS account snapshot and CloudTrail logs against "
        "CIS-style security controls.",
    )
    parser.add_argument("--version", action="version", version=f"cloudguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="run the security audit")
    audit.add_argument(
        "--snapshot",
        required=True,
        type=Path,
        help="path to the account configuration snapshot (JSON)",
    )
    audit.add_argument(
        "--cloudtrail",
        type=Path,
        default=None,
        help="path to CloudTrail events (JSONL or Records envelope)",
    )
    audit.add_argument(
        "--format",
        choices=sorted(_RENDERERS),
        default="console",
        help="output format (default: console)",
    )
    audit.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write the report to this file instead of stdout",
    )
    audit.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity if s is not Severity.INFO],
        default=None,
        help="exit non-zero if any finding is at or above this severity",
    )
    return parser


def _render(result: AuditResult, fmt: str) -> str:
    if fmt == "console":
        # Disable colour when writing to a file/pipe; render_console auto-detects.
        return render_console(result)
    return _RENDERERS[fmt](result)


def _exit_code(result: AuditResult, fail_on: str | None) -> int:
    if fail_on is None:
        return 0
    threshold = Severity.from_label(fail_on)
    worst = result.highest_severity()
    return 2 if worst.rank >= threshold.rank and result.findings else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        snapshot = load_snapshot(args.snapshot)
        events = load_cloudtrail_events(args.cloudtrail) if args.cloudtrail else []
    except (SnapshotError, CloudTrailError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    result = run_audit(snapshot, events)
    rendered = _render(result, args.format)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(
            f"Wrote {args.format} report to {args.output} "
            f"(score {result.score}/100, grade {result.grade})",
            file=sys.stderr,
        )
    else:
        print(rendered)

    return _exit_code(result, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
