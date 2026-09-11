"""Worker lifecycle coverage for Phase 3."""

from __future__ import annotations

import asyncio

from sqlalchemy import func, select

from safescope_core.models import (
    AuditLog,
    Base,
    Evidence,
    Finding,
    Organization,
    Project,
    ScanJob,
    ScanRun,
    Target,
    create_engine,
    create_session_factory,
)
from safescope_core.policy import Mode, Risk, ScanPolicyEngine, TargetSpec
from safescope_scanners.base import RawObservation, ScanContext, Scanner, Severity
from worker import cli


class FailingScanner(Scanner):
    id = "controlled-failure"
    name = "Controlled failure"
    risk = Risk.PASSIVE

    async def scan(self, _context):
        raise RuntimeError("controlled scanner failure")


class PassingScanner(Scanner):
    id = "controlled-success"
    name = "Controlled success"
    risk = Risk.PASSIVE

    async def scan(self, context: ScanContext) -> list[RawObservation]:
        return [
            RawObservation(
                title="Stable finding",
                severity=Severity.LOW,
                url=context.target_base_url,
                detail="Stable detail",
                confidence=0.9,
                evidence={"header": "missing"},
                remediation="Add the header.",
            )
        ]


def test_worker_marks_failed_jobs_and_writes_audit_log(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'worker.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(cli, "ALL_PASSIVE_SCANNERS", [FailingScanner])

    async def run() -> None:
        engine = create_engine(database_url)
        sessions = create_session_factory(engine)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                organization = Organization(name="Worker Test")
                session.add(organization)
                await session.flush()
                project = Project(organization_id=organization.id, name="Worker")
                session.add(project)
                await session.flush()
                target = Target(
                    project_id=project.id,
                    base_url="https://example.com",
                    root_domain="example.com",
                )
                session.add(target)
                await session.flush()
                snapshot = ScanPolicyEngine().freeze(
                    TargetSpec(target.base_url, target.root_domain, False, Mode.PASSIVE),
                    None,
                    [FailingScanner().to_spec()],
                )
                job = ScanJob(
                    target_id=target.id,
                    mode=Mode.PASSIVE.value,
                    policy_snapshot=snapshot,
                )
                session.add(job)
                await session.commit()

            assert await cli.run_once("test-worker") == 1

            async with sessions() as session:
                stored_job = await session.get(ScanJob, job.id)
                run_item = await session.scalar(select(ScanRun))
                audit = await session.scalar(select(AuditLog))
                assert stored_job is not None and stored_job.status == "FAILED"
                assert run_item is not None and run_item.status == "FAILED"
                assert run_item.finished_at is not None
                assert audit is not None and audit.result == "FAILED"
                assert audit.details["error_type"] == "RuntimeError"
        finally:
            await engine.dispose()

    asyncio.run(run())


def test_worker_completes_jobs_and_deduplicates_findings(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'worker-success.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(cli, "ALL_PASSIVE_SCANNERS", [PassingScanner])

    async def run() -> None:
        engine = create_engine(database_url)
        sessions = create_session_factory(engine)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                organization = Organization(name="Success Test")
                session.add(organization)
                await session.flush()
                project = Project(organization_id=organization.id, name="Worker")
                session.add(project)
                await session.flush()
                target = Target(
                    project_id=project.id,
                    base_url="https://example.com",
                    root_domain="example.com",
                )
                session.add(target)
                await session.flush()
                snapshot = ScanPolicyEngine().freeze(
                    TargetSpec(target.base_url, target.root_domain, False, Mode.PASSIVE),
                    None,
                    [PassingScanner().to_spec()],
                )
                session.add(
                    ScanJob(
                        target_id=target.id,
                        mode=Mode.PASSIVE.value,
                        policy_snapshot=snapshot,
                    )
                )
                await session.commit()

            assert await cli.run_once("test-worker") == 1

            async with sessions() as session:
                session.add(
                    ScanJob(
                        target_id=target.id,
                        mode=Mode.PASSIVE.value,
                        policy_snapshot=snapshot,
                    )
                )
                await session.commit()

            assert await cli.run_once("test-worker") == 1

            async with sessions() as session:
                finding_count = await session.scalar(select(func.count(Finding.id)))
                evidence_count = await session.scalar(select(func.count(Evidence.id)))
                completed_count = await session.scalar(
                    select(func.count(ScanJob.id)).where(ScanJob.status == "COMPLETED")
                )
                assert finding_count == 1
                assert evidence_count == 2
                assert completed_count == 2
        finally:
            await engine.dispose()

    asyncio.run(run())
