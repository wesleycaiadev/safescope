"""Database configuration for the local-first SafeScope MVP."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


def async_database_url(url: str) -> str:
    """Convert supported local and production URLs to async SQLAlchemy dialects."""
    if url.startswith("sqlite:///") and not url.startswith("sqlite+aiosqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql+asyncpg://"):
        parsed = make_url(url)
        query = dict(parsed.query)
        sslmode = query.pop("sslmode", None)
        query.pop("channel_binding", None)
        if sslmode is not None:
            query["ssl"] = "require" if sslmode in {"require", "verify-ca", "verify-full"} else sslmode
        return parsed.set(query=query).render_as_string(hide_password=False)
    return url


def create_engine(url: str = "sqlite:///./safescope.db") -> AsyncEngine:
    """Create the application's async engine without opening a connection."""
    return create_async_engine(async_database_url(url), future=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build a session factory suitable for API handlers and local workers."""
    return async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def session_scope(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession]:
    """Yield a transaction that commits on success and rolls back on failure."""
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
