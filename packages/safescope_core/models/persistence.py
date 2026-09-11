"""Persistence models. Business policy remains in :mod:`safescope_core.policy`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    """Create opaque identifiers without exposing database sequence numbers."""
    return str(uuid4())


def now_utc() -> datetime:
    """Return an aware UTC timestamp for persistent audit fields."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class OrganizationMember(Base):
    """A Supabase Auth user role within one tenant organization."""

    __tablename__ = "organization_memberships"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    role: Mapped[str] = mapped_column(String(16), default="MEMBER", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="LEAD", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), unique=True, nullable=False)
    root_domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mode: Mapped[str] = mapped_column(String(16), default="PASSIVE", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Scope(Base):
    __tablename__ = "scopes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True, nullable=False)
    origin: Mapped[str] = mapped_column(String(512), nullable=False)
    is_excluded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    path_pattern: Mapped[str | None] = mapped_column(String(2048))
    allowed_verbs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class Authorization(Base):
    __tablename__ = "authorizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True, nullable=False)
    representative_name: Mapped[str] = mapped_column(String(200), nullable=False)
    representative_email: Mapped[str] = mapped_column(String(320), nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    active_testing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_mutations: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allowed_verbs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    max_requests: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    max_rps: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class DomainVerification(Base):
    __tablename__ = "domain_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True, nullable=False)
    method: Mapped[str] = mapped_column(String(32), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True, nullable=False)
    authorization_id: Mapped[str | None] = mapped_column(ForeignKey("authorizations.id"), index=True)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), unique=True, nullable=False)
    worker_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True, nullable=False)
    scan_run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    sanitized_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id"), index=True)
    authorization_id: Mapped[str | None] = mapped_column(ForeignKey("authorizations.id"), index=True)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
