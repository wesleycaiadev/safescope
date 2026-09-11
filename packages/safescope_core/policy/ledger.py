"""ResourceLedger — tracks everything the platform creates on the target.

Write operations only pass the gate if the resource is in the ledger
OR on the allow_write_paths list with a snapshot captured.

This is what makes the guarantee: "nothing is written without the platform
knowing the address". Cleanup uses this to delete what was created.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class LedgerEntry:
    """A resource created by the scan on the target."""

    url: str
    verb: str
    marker: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    cleaned: bool = False
    cleanup_error: str | None = None


class ResourceLedger:
    """Tracks resources created during a scan run.

    Rules:
    1. POST that creates a resource → record_create() with __SPROOF_ marker
    2. PUT/PATCH/DELETE on a URL not in the ledger → requires allow_write_paths + snapshot()
    3. Cleanup at end → iterate pending() and DELETE each, confirm removal
    4. Finding with cleanup_state != CLEANED appears with warning in the report
    """

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._created: dict[str, LedgerEntry] = {}
        self._state_before: dict[str, dict[str, Any]] = {}

    def record_create(self, url: str, verb: str, marker: str) -> None:
        """Register a resource created by this scan.

        If the URL was already created in this scan, reuse the entry
        (case 10 of the policy matrix: same URL already ledgered → reuse).
        """
        if url in self._created:
            # Already tracked — update verb if needed but don't duplicate
            return
        self._created[url] = LedgerEntry(url=url, verb=verb, marker=marker)

    def owns(self, url: str) -> bool:
        """True if the URL was created by this scan."""
        return url in self._created

    def snapshot(self, url: str, state: dict[str, Any]) -> None:
        """Capture state before mutating an existing resource (not created by us).

        This is required for case 9 of the policy matrix:
        DESTRUCTIVE + authz valid + mutations on existing resource
        → must snapshot() before DELETE, restore in finally.
        """
        self._state_before.setdefault(url, state)

    def has_snapshot(self, url: str) -> bool:
        """True if we captured state_before for this URL."""
        return url in self._state_before

    def restore_plan(self) -> dict[str, dict[str, Any]]:
        """Return URLs with their captured state for restoration."""
        return dict(self._state_before)

    def mark_cleaned(self, url: str) -> None:
        """Mark a created resource as successfully cleaned up."""
        if url in self._created:
            self._created[url].cleaned = True

    def mark_cleanup_failed(self, url: str, error: str) -> None:
        """Mark a cleanup attempt as failed. Will appear in the report."""
        if url in self._created:
            self._created[url].cleanup_error = error

    def pending(self) -> list[str]:
        """URLs of resources created by this scan that haven't been cleaned up yet."""
        return [url for url, entry in self._created.items() if not entry.cleaned]

    def all_entries(self) -> list[LedgerEntry]:
        """All entries, for audit and report generation."""
        return list(self._created.values())

    @property
    def created_count(self) -> int:
        return len(self._created)

    @property
    def cleaned_count(self) -> int:
        return sum(1 for e in self._created.values() if e.cleaned)
