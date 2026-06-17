"""Check protocol, audit context, and the global check registry.

A *check* is a small pure function that receives an :class:`AuditContext` and
yields zero or more :class:`~cloudguard.models.Finding` objects. Checks register
themselves with the :func:`check` decorator, which records their
:class:`~cloudguard.models.CheckMeta` so the engine can enumerate, count and
report them without importing each module by hand.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

from cloudguard.ingest import AccountSnapshot, CloudTrailEvent
from cloudguard.models import CheckMeta, Finding, Severity


@dataclass(frozen=True, slots=True)
class AuditContext:
    """Everything a check is allowed to read."""

    snapshot: AccountSnapshot
    events: tuple[CloudTrailEvent, ...] = field(default_factory=tuple)


# A check takes a context and yields findings.
CheckFn = Callable[[AuditContext], Iterable[Finding]]

# The registry preserves insertion order so reports are deterministic.
_REGISTRY: list[tuple[CheckMeta, CheckFn]] = []


def check(
    *,
    check_id: str,
    title: str,
    category: str,
    default_severity: Severity,
    cis_control: str | None = None,
) -> Callable[[CheckFn], CheckFn]:
    """Register a check function and attach its metadata.

    Raises:
        ValueError: if ``check_id`` is already registered (guards copy-paste
            mistakes that would otherwise silently shadow a check).
    """

    def decorator(func: CheckFn) -> CheckFn:
        if any(meta.check_id == check_id for meta, _ in _REGISTRY):
            raise ValueError(f"duplicate check_id registered: {check_id!r}")
        meta = CheckMeta(
            check_id=check_id,
            title=title,
            category=category,
            default_severity=default_severity,
            cis_control=cis_control,
        )
        _REGISTRY.append((meta, func))
        return func

    return decorator


def registered_checks() -> list[tuple[CheckMeta, CheckFn]]:
    """Return all registered checks in registration order (a copy)."""
    return list(_REGISTRY)


def run_check(func: CheckFn, ctx: AuditContext) -> Iterator[Finding]:
    """Execute a single check, yielding its findings."""
    yield from func(ctx)
