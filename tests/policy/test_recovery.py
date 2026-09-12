"""Crash-safe restore journal and replay tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace

from safescope_core.policy import (
    RequestDescriptor,
    ResponseData,
    RestoreAction,
    RestoreKind,
    replay_restore_journal,
)
from worker.restore_journal import FileRestoreJournal


def _action() -> RestoreAction:
    return RestoreAction(
        id="restore-1",
        scan_run_id="run-1",
        kind=RestoreKind.DELETE_CREATED,
        request=RequestDescriptor("DELETE", "https://target.test/api/canaries/one"),
        policy_snapshot={"mode": "AGGRESSIVE"},
        marker="__SPROOF_run-1",
    )


def test_file_journal_survives_reopen_and_completes_atomically(tmp_path) -> None:
    journal = FileRestoreJournal(tmp_path / "journal")
    journal.append(_action())
    reopened = FileRestoreJournal(tmp_path / "journal")
    assert reopened.pending()[0].request.url.endswith("/one")
    assert oct((tmp_path / "journal" / "restore-1.json").stat().st_mode & 0o777) == "0o600"

    async def run() -> None:
        summary = await replay_restore_journal(reopened, lambda _action: _response(204))
        assert summary.completed == 1
        assert reopened.pending() == []

    asyncio.run(run())


def test_failed_recovery_remains_pending_for_bounded_retry(tmp_path) -> None:
    journal = FileRestoreJournal(tmp_path / "journal")
    journal.append(_action())

    async def run() -> None:
        summary = await replay_restore_journal(journal, lambda _action: _response(500))
        assert summary.failed == 1
        pending = journal.pending()
        assert pending[0].attempts == 1
        assert "HTTP 500" in (pending[0].last_error or "")

    asyncio.run(run())


def test_exhausted_action_remains_an_unresolved_blocker(tmp_path) -> None:
    journal = FileRestoreJournal(tmp_path / "journal")
    action = replace(_action(), attempts=3)
    journal.append(action)
    assert journal.pending() == []
    assert journal.unresolved_count() == 1


async def _response(status: int) -> ResponseData:
    return ResponseData(status)
