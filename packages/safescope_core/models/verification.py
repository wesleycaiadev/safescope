"""Domain ownership verification without persisting the raw challenge token."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Collection
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from safescope_core.policy import RequestDescriptor, ResponseData

if TYPE_CHECKING:
    from .persistence import Target
    from .repository import TargetRepository

RequestExecutor = Callable[[RequestDescriptor], Awaitable[ResponseData]]


class DomainVerifier:
    """Validate public proof material before consuming a stored challenge."""

    def __init__(self, repository: TargetRepository) -> None:
        self._repository = repository

    async def verify_well_known(self, target: Target, token: str, request: RequestExecutor) -> bool:
        """Verify an exact token line at the target's public well-known path."""
        response = await request(RequestDescriptor("GET", _well_known_url(target.base_url)))
        if response.status_code != 200:
            return False
        expected = f"SAFESCOPE_VERIFICATION={token}"
        lines = response.body.decode("utf-8", errors="replace").splitlines()
        if expected not in (line.strip() for line in lines):
            return False
        return await self._repository.consume_challenge(target.id, token)

    async def verify_dns_txt(self, target: Target, token: str, records: Collection[str]) -> bool:
        """Verify an exact DNS TXT value supplied by a DNS resolver adapter."""
        expected = f"SAFESCOPE_VERIFICATION={token}"
        if expected not in {record.strip().strip('"') for record in records}:
            return False
        return await self._repository.consume_challenge(target.id, token)


def _well_known_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/safescope-verification.txt"
