"""Mutation planning and pre-write journaling tests."""

from __future__ import annotations

import asyncio

from safescope_core.policy import RequestDescriptor, ResourceLedger, ResponseData
from safescope_scanners.mutations import MutationPlan
from worker.restore_journal import FileRestoreJournal


def test_canary_restore_is_durable_before_create_request(tmp_path) -> None:
    async def run() -> None:
        journal = FileRestoreJournal(tmp_path / "journal")
        ledger = ResourceLedger("run-1")
        saw_pending_before_write = False

        async def send(request: RequestDescriptor) -> ResponseData:
            nonlocal saw_pending_before_write
            if request.method == "POST":
                saw_pending_before_write = len(journal.pending()) == 1
                return ResponseData(201)
            return ResponseData(204)

        plan = MutationPlan("run-1", {"mode": "AGGRESSIVE"}, ledger, journal, send)
        result = await plan.create_canary(
            RequestDescriptor("POST", "https://target.test/api/canaries"),
            RequestDescriptor("DELETE", "https://target.test/api/canaries/one"),
            "__SPROOF_run-1_one",
        )
        assert result.response.status_code == 201
        assert saw_pending_before_write is True
        assert ledger.owns("https://target.test/api/canaries/one")
        await plan.cleanup(result.restore_action)
        assert journal.pending() == []

    asyncio.run(run())


def test_existing_resource_snapshot_is_recorded_before_patch(tmp_path) -> None:
    async def run() -> None:
        journal = FileRestoreJournal(tmp_path / "journal")
        ledger = ResourceLedger("run-2")

        async def send(_request: RequestDescriptor) -> ResponseData:
            assert journal.pending()
            assert ledger.has_snapshot("https://target.test/api/profile/me")
            return ResponseData(200)

        plan = MutationPlan("run-2", {"mode": "AGGRESSIVE"}, ledger, journal, send)
        await plan.modify_with_snapshot(
            RequestDescriptor("PATCH", "https://target.test/api/profile/me", body=b'{"name":"canary"}'),
            RequestDescriptor("PUT", "https://target.test/api/profile/me", body=b'{"name":"before"}'),
            {"name": "before"},
            "__SPROOF_run-2_profile",
        )

    asyncio.run(run())
