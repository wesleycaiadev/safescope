"""Crash-safe restoration contracts and replay orchestration."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from typing import Any

    from .request import RequestDescriptor, ResponseData


class RestoreKind(enum.StrEnum):
    DELETE_CREATED = "DELETE_CREATED"
    RESTORE_SNAPSHOT = "RESTORE_SNAPSHOT"


@dataclass(frozen=True)
class RestoreAction:
    id: str
    scan_run_id: str
    kind: RestoreKind
    request: RequestDescriptor
    policy_snapshot: dict[str, Any]
    marker: str
    attempts: int = 0
    max_attempts: int = 3
    last_error: str | None = None


@dataclass(frozen=True)
class RecoverySummary:
    attempted: int
    completed: int
    failed: int


class RestoreJournal(Protocol):
    def append(self, action: RestoreAction) -> None: ...

    def pending(self) -> list[RestoreAction]: ...

    def mark_completed(self, action_id: str) -> None: ...

    def mark_failed(self, action_id: str, error: str) -> None: ...


async def replay_restore_journal(
    journal: RestoreJournal,
    execute: Callable[[RestoreAction], Awaitable[ResponseData]],
) -> RecoverySummary:
    """Replay pending actions and retain failures for the next boot."""
    attempted = completed = failed = 0
    for action in journal.pending():
        attempted += 1
        try:
            response = await execute(action)
            success = 200 <= response.status_code < 300
            if action.kind is RestoreKind.DELETE_CREATED and response.status_code == 404:
                success = True
            if not success:
                raise RuntimeError(f"restore returned HTTP {response.status_code}")
        except Exception as error:
            failed += 1
            journal.mark_failed(action.id, f"{type(error).__name__}: {error}"[:500])
        else:
            completed += 1
            journal.mark_completed(action.id)
    return RecoverySummary(attempted, completed, failed)
