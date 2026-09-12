"""Mutation coordinator that journals restoration before any target write."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from uuid import uuid4

from safescope_core.policy import RequestDescriptor, RestoreAction, RestoreKind

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from typing import Any

    from safescope_core.policy import ResourceLedger, ResponseData, RestoreJournal


@dataclass(frozen=True)
class MutationResult:
    response: ResponseData
    restore_action: RestoreAction


class MutationPlan:
    """Persist rollback intent first, then let the gated transport write."""

    def __init__(
        self,
        scan_run_id: str,
        policy_snapshot: dict[str, Any],
        ledger: ResourceLedger,
        journal: RestoreJournal,
        send: Callable[[RequestDescriptor], Awaitable[ResponseData]],
    ) -> None:
        self._scan_run_id = scan_run_id
        self._policy_snapshot = policy_snapshot
        self._ledger = ledger
        self._journal = journal
        self._send = send

    async def create_canary(
        self,
        create_request: RequestDescriptor,
        cleanup_request: RequestDescriptor,
        marker: str,
    ) -> MutationResult:
        """Create only a marked canary with a pre-journaled DELETE cleanup."""
        expected_prefix = f"__SPROOF_{self._scan_run_id}_"
        if not marker.startswith(expected_prefix):
            raise ValueError(f"canary marker must start with '{expected_prefix}'")
        if create_request.method.upper() != "POST" or cleanup_request.method.upper() != "DELETE":
            raise ValueError("canary creation requires POST and cleanup requires DELETE")
        if _origin(create_request.url) != _origin(cleanup_request.url):
            raise ValueError("create and cleanup requests must use the same origin")

        action = RestoreAction(
            id=f"restore-{uuid4().hex}",
            scan_run_id=self._scan_run_id,
            kind=RestoreKind.DELETE_CREATED,
            request=cleanup_request,
            policy_snapshot=self._policy_snapshot,
            marker=marker,
        )
        self._journal.append(action)
        self._ledger.record_create(cleanup_request.url, "POST", marker)
        response = await self._send(create_request)
        return MutationResult(response, action)

    async def modify_with_snapshot(
        self,
        mutation_request: RequestDescriptor,
        restore_request: RequestDescriptor,
        state_before: dict[str, Any],
        marker: str,
    ) -> MutationResult:
        """Journal an exact PUT/PATCH restore before modifying an allowed path."""
        if mutation_request.method.upper() not in {"PUT", "PATCH"}:
            raise ValueError("existing resources may only be changed with PUT or PATCH")
        if restore_request.method.upper() not in {"PUT", "PATCH"}:
            raise ValueError("snapshot restoration requires PUT or PATCH")
        if mutation_request.url != restore_request.url:
            raise ValueError("mutation and restoration must address the same URL")

        action = RestoreAction(
            id=f"restore-{uuid4().hex}",
            scan_run_id=self._scan_run_id,
            kind=RestoreKind.RESTORE_SNAPSHOT,
            request=restore_request,
            policy_snapshot=self._policy_snapshot,
            marker=marker,
        )
        self._journal.append(action)
        self._ledger.snapshot(mutation_request.url, state_before)
        response = await self._send(mutation_request)
        return MutationResult(response, action)

    async def cleanup(self, action: RestoreAction) -> ResponseData:
        """Execute one restore now; crash recovery handles any unfinished action."""
        try:
            response = await self._send(action.request)
            success = 200 <= response.status_code < 300
            if action.kind is RestoreKind.DELETE_CREATED and response.status_code == 404:
                success = True
            if not success:
                raise RuntimeError(f"cleanup returned HTTP {response.status_code}")
        except Exception as error:
            self._journal.mark_failed(action.id, f"{type(error).__name__}: {error}"[:500])
            raise
        self._journal.mark_completed(action.id)
        return response


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
