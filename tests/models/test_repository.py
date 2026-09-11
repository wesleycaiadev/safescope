"""SQLite persistence and ownership challenge tests."""

from __future__ import annotations

import asyncio

from safescope_core.models import (
    Base,
    DomainVerifier,
    Organization,
    Project,
    Target,
    TargetRepository,
    create_engine,
    create_session_factory,
)
from safescope_core.policy import ResponseData


def test_postgresql_urls_use_asyncpg() -> None:
    engine = create_engine("postgresql://user:secret@example.test:5432/safescope")
    try:
        assert engine.url.drivername == "postgresql+asyncpg"
    finally:
        asyncio.run(engine.dispose())


def test_challenge_is_stored_hashed_consumed_once_and_verifies_target(tmp_path) -> None:
    async def run() -> None:
        engine = create_engine(f"sqlite:///{tmp_path / 'scope.db'}")
        session_factory = create_session_factory(engine)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

            async with session_factory() as session:
                organization = Organization(name="Acme Ltda")
                session.add(organization)
                await session.flush()
                project = Project(organization_id=organization.id, name="Pre-auditoria")
                session.add(project)
                await session.flush()
                target = Target(
                    project_id=project.id,
                    base_url="https://acme.example",
                    root_domain="acme.example",
                )
                session.add(target)
                await session.flush()

                repository = TargetRepository(session)
                challenge, token = await repository.create_challenge(target.id, method="DNS_TXT")
                assert challenge.token_digest != token
                assert await repository.consume_challenge(target.id, token) is True
                assert target.verified is True
                assert challenge.consumed_at is not None
                assert await repository.consume_challenge(target.id, token) is False
        finally:
            await engine.dispose()

    asyncio.run(run())


def test_well_known_proof_consumes_a_matching_challenge(tmp_path) -> None:
    async def run() -> None:
        engine = create_engine(f"sqlite:///{tmp_path / 'verify.db'}")
        session_factory = create_session_factory(engine)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with session_factory() as session:
                organization = Organization(name="Verifier Ltda")
                session.add(organization)
                await session.flush()
                project = Project(organization_id=organization.id, name="Verification")
                session.add(project)
                await session.flush()
                target = Target(
                    project_id=project.id,
                    base_url="https://verifier.example/app",
                    root_domain="verifier.example",
                )
                session.add(target)
                await session.flush()
                repository = TargetRepository(session)
                _challenge, token = await repository.create_challenge(target.id, method="WELL_KNOWN")

                async def request(descriptor):
                    assert descriptor.url == "https://verifier.example/.well-known/safescope-verification.txt"
                    return ResponseData(200, body=f"SAFESCOPE_VERIFICATION={token}\n".encode())

                assert await DomainVerifier(repository).verify_well_known(target, token, request)
                assert target.verified is True
        finally:
            await engine.dispose()

    asyncio.run(run())
