"""Small repositories for persistence operations used by the MVP."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select

from .persistence import DomainVerification, Target

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class TargetRepository:
    """Persistence boundary for targets and one-use ownership challenges."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_target(self, target_id: str) -> Target | None:
        return await self._session.get(Target, target_id)

    async def create_challenge(
        self,
        target_id: str,
        *,
        method: str,
        ttl: timedelta = timedelta(hours=24),
    ) -> tuple[DomainVerification, str]:
        """Create a challenge; only its SHA-256 digest is stored."""
        token = secrets.token_urlsafe(32)
        challenge = DomainVerification(
            target_id=target_id,
            method=method,
            token_digest=_digest(token),
            expires_at=datetime.now(UTC) + ttl,
        )
        self._session.add(challenge)
        await self._session.flush()
        return challenge, token

    async def consume_challenge(self, target_id: str, token: str) -> bool:
        """Atomically consume a live matching token and mark the target verified."""
        now = datetime.now(UTC)
        result = await self._session.execute(
            select(DomainVerification)
            .where(
                DomainVerification.target_id == target_id,
                DomainVerification.consumed_at.is_(None),
                DomainVerification.expires_at > now,
            )
            .order_by(DomainVerification.created_at.desc())
        )
        for challenge in result.scalars():
            if hmac.compare_digest(challenge.token_digest, _digest(token)):
                target = await self.get_target(target_id)
                if target is None:
                    return False
                challenge.consumed_at = now
                target.verified = True
                target.verified_at = now
                await self._session.flush()
                return True
        return False


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
