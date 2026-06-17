"""Machine-readable JSON report (CI-consumable)."""

from __future__ import annotations

import json

from cloudguard.models import AuditResult


def render_json(result: AuditResult, *, indent: int = 2) -> str:
    """Serialise the audit result as pretty-printed JSON."""
    return json.dumps(result.to_dict(), indent=indent, sort_keys=False)
