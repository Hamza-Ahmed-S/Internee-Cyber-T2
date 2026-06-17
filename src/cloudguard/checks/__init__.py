"""Compliance checks.

Importing this package registers every built-in check into the global
registry (see :mod:`cloudguard.checks.base`). The engine relies on this
side effect, so the submodules are imported here explicitly.
"""

from __future__ import annotations

from cloudguard.checks import cloudtrail_checks, config_checks  # noqa: F401
from cloudguard.checks.base import (
    AuditContext,
    CheckFn,
    check,
    registered_checks,
)

__all__ = ["AuditContext", "CheckFn", "check", "registered_checks"]
