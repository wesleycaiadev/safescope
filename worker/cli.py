"""Local worker command line. It deliberately runs only PASSIVE jobs for now."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from contextlib import suppress
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from dotenv import load_dotenv
from sqlalchemy import func, select

from safescope_core.models import (
    AuditLog,
    Evidence,
    Finding,
    NormalizedFinding,
    Project,
    ScanJob,
    ScanRun,
    Target,
    create_engine,
    create_session_factory,
    normalize_observations,
)
from safescope_core.policy import KillSwitch, Mode, RequestGate, ResourceLedger, SSRFGuard
from safescope_scanners import ALL_PASSIVE_SCANNERS
from safescope_scanners.base import ScanContext
from safescope_scanners.transport import GatedTransport

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

load_dotenv()
DATABASE_URL = "sqlite:///./safescope.db"


async def _write_audit(
    session: AsyncSession,
    target: Target,
    action: str,
    result: str,
    details: dict[str, object],
) -> None:
    project = await session.get(Project, target.project_id)
    if project is None:
        return
    session.add(
        AuditLog(
            organization_id=project.organization_id,
            actor="worker",
            action=action,
            target_id=target.id,
            result=result,
            details=details,
        )
    )


async def _persist_observation(
    session: AsyncSession,
    target: Target,
    run: ScanRun,
    scanner_id: str,
    item: NormalizedFinding,
) -> None:
    finding = await session.scalar(
        select(Finding).where(
            Finding.target_id == target.id,
            Finding.title == item.title,
        )
    )
    if finding is None:
        finding = Finding(
            target_id=target.id,
            title=item.title,
            severity=item.severity,
            confidence=item.confidence,
            description=item.description,
            remediation=item.remediation,
        )
        session.add(finding)
        await session.flush()
    else:
        finding.severity = item.severity
        finding.confidence = item.confidence
        finding.description = item.description
        finding.remediation = item.remediation
    session.add(
        Evidence(
            finding_id=finding.id,
            scan_run_id=run.id,
            source=scanner_id,
            url=item.url,
            sanitized_data=item.evidence,
            content_hash=item.evidence_hash,
        )
    )


async def run_once(worker_id: str) -> int:
    """Claim and execute one pending passive job; return 1 when a job was claimed."""
    engine = create_engine(os.getenv("DATABASE_URL", DATABASE_URL))
    sessions = create_session_factory(engine)
    try:
        async with sessions() as session:
            job = await session.scalar(
                select(ScanJob).where(ScanJob.status == "PENDING").order_by(ScanJob.created_at).limit(1)
            )
            if job is None:
                return 0
            target = await session.get(Target, job.target_id)
            if target is None or job.mode != Mode.PASSIVE.value or target.mode != Mode.PASSIVE.value:
                job.status = "REJECTED"
                await session.commit()
                return 1

            job.status = "RUNNING"
            run = ScanRun(job_id=job.id, worker_id=worker_id)
            session.add(run)
            await session.commit()

            try:
                gate = RequestGate(job.policy_snapshot, ResourceLedger(run.id), KillSwitch(), SSRFGuard())
                async with GatedTransport(gate) as transport:
                    context = ScanContext(
                        target.base_url,
                        transport.request,
                        gate.ledger,
                        tls=transport.probe_tls,
                        metadata={"policy_snapshot": job.policy_snapshot},
                    )
                    for scanner_class in ALL_PASSIVE_SCANNERS:
                        if scanner_class.id not in job.policy_snapshot.get("scanners_allowed", []):
                            continue
                        observations = await scanner_class().scan(context)
                        for item in normalize_observations(observations):
                            await _persist_observation(
                                session,
                                target,
                                run,
                                scanner_class.id,
                                item,
                            )
                run.status = "COMPLETED"
                run.finished_at = datetime.now(UTC)
                job.status = "COMPLETED"
                await _write_audit(
                    session,
                    target,
                    "PASSIVE_SCAN",
                    "COMPLETED",
                    {"job_id": job.id, "scan_run_id": run.id},
                )
                await session.commit()
            except Exception as error:
                await session.rollback()
                failed_job = await session.get(ScanJob, job.id)
                failed_run = await session.get(ScanRun, run.id)
                failed_target = await session.get(Target, target.id)
                if failed_job is not None:
                    failed_job.status = "FAILED"
                if failed_run is not None:
                    failed_run.status = "FAILED"
                    failed_run.finished_at = datetime.now(UTC)
                if failed_target is not None:
                    await _write_audit(
                        session,
                        failed_target,
                        "PASSIVE_SCAN",
                        "FAILED",
                        {
                            "job_id": job.id,
                            "scan_run_id": run.id,
                            "error_type": type(error).__name__,
                            "error": str(error)[:500],
                        },
                    )
                await session.commit()
            return 1
    finally:
        await engine.dispose()


async def run_forever(worker_id: str, poll_interval: float) -> None:
    """Poll SQLite continuously until interrupted."""
    while True:
        claimed = await run_once(worker_id)
        if not claimed:
            await asyncio.sleep(poll_interval)


async def worker_status() -> dict[str, int]:
    """Return queue counts without modifying any jobs."""
    engine = create_engine(os.getenv("DATABASE_URL", DATABASE_URL))
    sessions = create_session_factory(engine)
    try:
        async with sessions() as session:
            rows = await session.execute(select(ScanJob.status, func.count(ScanJob.id)).group_by(ScanJob.status))
            counts = {str(item[0]).lower(): int(item[1]) for item in rows}
            counts["total"] = sum(counts.values())
            return counts
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(prog="safescope")
    commands = parser.add_subparsers(dest="command", required=True)
    worker = commands.add_parser("worker", help="Run or inspect the local worker")
    worker.add_argument("action", choices=["once", "start", "status"])
    worker.add_argument("--id", default=os.getenv("WORKER_ID", "worker-local-01"))
    worker.add_argument("--poll-interval", type=float, default=2.0)
    arguments = parser.parse_args()
    if arguments.command != "worker":
        return
    if arguments.action == "once":
        asyncio.run(run_once(arguments.id))
    elif arguments.action == "start":
        with suppress(KeyboardInterrupt):
            asyncio.run(run_forever(arguments.id, max(0.2, arguments.poll_interval)))
    else:
        print(json.dumps(asyncio.run(worker_status()), indent=2, sort_keys=True))
