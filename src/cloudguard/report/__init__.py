"""Report renderers: turn an :class:`~cloudguard.models.AuditResult` into text."""

from __future__ import annotations

from cloudguard.report.console import render_console
from cloudguard.report.json_report import render_json
from cloudguard.report.markdown import render_markdown

__all__ = ["render_console", "render_json", "render_markdown"]
