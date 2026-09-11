"""Local FastAPI control plane for SafeScope's passive MVP."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Literal
from urllib.parse import urlsplit

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.auth import (
    Actor,
    Principal,
    organization_for_project,
    organization_for_target,
    require_organization_access,
    visible_organization_ids,
)
from safescope_core.models import (
    AuditLog,
    Authorization,
    Base,
    Evidence,
    Finding,
    Organization,
    OrganizationMember,
    Project,
    ScanJob,
    ScanRun,
    Scope,
    Target,
    create_engine,
    create_session_factory,
)
from safescope_core.policy import Mode, ScanPolicyEngine, TargetSpec
from safescope_core.scoring import Confidence, ScoreInput, calculate_security_score
from safescope_report import (
    EngagementTemplateInput,
    ReportEvidence,
    ReportFinding,
    ReportInput,
    generate_pdf,
    proposal_markdown,
    roe_markdown,
)
from safescope_scanners import PASSIVE_SCANNERS, ZapBaselineScanner, zap_available

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator

    from safescope_scanners.base import Scanner

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./safescope.db")
engine = create_engine(DATABASE_URL)
session_factory = create_session_factory(engine)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="SafeScope API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["content-type", "authorization"],
)


async def session() -> AsyncIterator[AsyncSession]:
    async with session_factory() as database_session:
        try:
            yield database_session
            await database_session.commit()
        except BaseException:
            await database_session.rollback()
            raise


Database = Annotated[AsyncSession, Depends(session)]


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class OrganizationUpdate(OrganizationCreate):
    pass


class OrganizationView(ApiModel):
    id: str
    name: str
    created_at: datetime


class OrganizationMemberCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)
    role: Literal["VIEWER", "MEMBER", "ADMIN", "OWNER"] = "MEMBER"


class OrganizationMemberView(ApiModel):
    organization_id: str
    user_id: str
    role: str
    created_at: datetime


class ProjectCreate(BaseModel):
    organization_id: str
    name: str = Field(min_length=1, max_length=200)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    status: Literal["LEAD", "ACTIVE", "ARCHIVED"] | None = None


class ProjectView(ApiModel):
    id: str
    organization_id: str
    name: str
    status: str
    created_at: datetime


class TargetCreate(BaseModel):
    project_id: str
    base_url: HttpUrl


class TargetUpdate(BaseModel):
    base_url: HttpUrl


class TargetView(ApiModel):
    id: str
    project_id: str
    base_url: str
    root_domain: str
    verified: bool
    mode: str
    created_at: datetime


class ScanJobCreate(BaseModel):
    target_id: str
    include_zap_baseline: bool = False


class ScanJobView(ApiModel):
    id: str
    target_id: str
    mode: str
    status: str
    created_at: datetime


class ScanRunView(ApiModel):
    id: str
    job_id: str
    worker_id: str
    status: str
    started_at: datetime
    finished_at: datetime | None


class ScopeCreate(BaseModel):
    target_id: str
    origin: HttpUrl
    is_excluded: bool = False
    path_pattern: str | None = Field(default=None, max_length=2048)


class ScopeUpdate(BaseModel):
    origin: HttpUrl | None = None
    is_excluded: bool | None = None
    path_pattern: str | None = Field(default=None, max_length=2048)


class ScopeView(ApiModel):
    id: str
    target_id: str
    origin: str
    is_excluded: bool
    path_pattern: str | None
    allowed_verbs: list[str]


class AuthorizationCreate(BaseModel):
    target_id: str
    representative_name: str = Field(min_length=1, max_length=200)
    representative_email: str = Field(min_length=3, max_length=320)
    valid_from: datetime
    valid_until: datetime


class AuthorizationUpdate(BaseModel):
    representative_name: str | None = Field(default=None, min_length=1, max_length=200)
    representative_email: str | None = Field(default=None, min_length=3, max_length=320)
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class AuthorizationView(ApiModel):
    id: str
    target_id: str
    representative_name: str
    representative_email: str
    accepted_at: datetime
    valid_from: datetime
    valid_until: datetime
    active_testing: bool
    allow_mutations: bool


class FindingView(ApiModel):
    id: str
    target_id: str
    title: str
    severity: str
    confidence: float
    status: str
    description: str
    remediation: str | None
    created_at: datetime


class FindingStatusUpdate(BaseModel):
    status: Literal["OPEN", "ACKNOWLEDGED", "FIXED", "ACCEPTED_RISK"]


class EvidenceView(ApiModel):
    id: str
    finding_id: str
    scan_run_id: str
    source: str
    url: str
    status_code: int | None
    sanitized_data: dict[str, object]
    content_hash: str
    observed_at: datetime


class AuditLogView(ApiModel):
    id: str
    organization_id: str
    actor: str
    action: str
    target_id: str | None
    result: str
    details: dict[str, object]
    occurred_at: datetime


class SummaryView(BaseModel):
    score: int
    deductions: int
    open_findings: int
    total_findings: int
    targets: int
    pending_jobs: int
    running_jobs: int
    completed_jobs: int


def _confidence(value: float) -> Confidence:
    if value >= 0.9:
        return Confidence.CONFIRMED
    if value >= 0.65:
        return Confidence.LIKELY
    return Confidence.POTENTIAL


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def _report_input(target_id: str, database: AsyncSession, actor: Principal) -> ReportInput:
    target = await database.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    project = await database.get(Project, target.project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    organization = await database.get(Organization, project.organization_id)
    if organization is None:
        raise HTTPException(404, "Organization not found")
    await require_organization_access(database, actor, organization.id)

    scopes = list((await database.scalars(select(Scope).where(Scope.target_id == target.id))).all())
    findings = list(
        (
            await database.scalars(
                select(Finding).where(Finding.target_id == target.id).order_by(Finding.created_at.desc())
            )
        ).all()
    )
    evidence_by_finding: dict[str, list[ReportEvidence]] = {}
    if findings:
        evidence_items = list(
            (
                await database.scalars(
                    select(Evidence)
                    .where(Evidence.finding_id.in_([item.id for item in findings]))
                    .order_by(Evidence.observed_at.desc())
                )
            ).all()
        )
        for item in evidence_items:
            evidence_by_finding.setdefault(item.finding_id, []).append(
                ReportEvidence(
                    source=item.source,
                    url=item.url,
                    observed_at=item.observed_at,
                    sanitized_data=item.sanitized_data,
                )
            )
    report_findings = tuple(
        ReportFinding(
            id=item.id,
            title=item.title,
            severity=item.severity,
            confidence=item.confidence,
            status=item.status,
            description=item.description,
            remediation=item.remediation,
            created_at=item.created_at,
            evidence=tuple(evidence_by_finding.get(item.id, [])),
        )
        for item in findings
    )
    return ReportInput(
        organization_name=organization.name,
        project_name=project.name,
        target_url=target.base_url,
        target_verified=target.verified,
        created_at=datetime.now(UTC),
        scopes=tuple(item.origin for item in scopes if not item.is_excluded),
        exclusions=tuple(f"{item.origin}{item.path_pattern or '*'}" for item in scopes if item.is_excluded),
        findings=report_findings,
        report_id=target.id,
    )


async def _write_audit(
    database: AsyncSession,
    organization_id: str,
    actor: Principal,
    action: str,
    *,
    target_id: str | None = None,
    details: dict[str, object] | None = None,
) -> None:
    """Write a compact event; production denies later updates/deletes at the database."""
    database.add(
        AuditLog(
            organization_id=organization_id,
            actor=actor.user_id,
            action=action,
            target_id=target_id,
            result="SUCCESS",
            details=details or {},
        )
    )


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "SafeScope API", "health": "/health", "docs": "/docs"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/organizations", response_model=list[OrganizationView])
async def list_organizations(database: Database, actor: Actor) -> list[Organization]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(Organization).where(Organization.id.in_(organization_ids)).order_by(Organization.created_at.desc())
    return list((await database.scalars(query)).all())


@app.post("/organizations", status_code=status.HTTP_201_CREATED, response_model=OrganizationView)
async def create_organization(payload: OrganizationCreate, database: Database, actor: Actor) -> Organization:
    name = payload.name.strip()
    if not name:
        raise HTTPException(422, "Organization name cannot be blank")
    existing = await database.scalar(select(Organization).where(Organization.name == name))
    if existing is not None:
        raise HTTPException(409, "Organization already exists")
    organization = Organization(name=name)
    database.add(organization)
    await database.flush()
    database.add(OrganizationMember(organization_id=organization.id, user_id=actor.user_id, role="OWNER"))
    await _write_audit(database, organization.id, actor, "ORGANIZATION_CREATED", details={"name": organization.name})
    return organization


@app.patch("/organizations/{organization_id}", response_model=OrganizationView)
async def update_organization(
    organization_id: str,
    payload: OrganizationUpdate,
    database: Database,
    actor: Actor,
) -> Organization:
    organization = await require_organization_access(database, actor, organization_id, "ADMIN")
    name = payload.name.strip()
    if not name:
        raise HTTPException(422, "Organization name cannot be blank")
    existing = await database.scalar(
        select(Organization).where(
            Organization.name == name,
            Organization.id != organization.id,
        )
    )
    if existing is not None:
        raise HTTPException(409, "Organization already exists")
    organization.name = name
    await _write_audit(database, organization.id, actor, "ORGANIZATION_UPDATED")
    await database.flush()
    return organization


@app.delete("/organizations/{organization_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(organization_id: str, database: Database, actor: Actor) -> Response:
    organization = await require_organization_access(database, actor, organization_id, "OWNER")
    project_id = await database.scalar(select(Project.id).where(Project.organization_id == organization.id))
    if project_id:
        raise HTTPException(409, "Remove the organization's projects first")
    await database.delete(organization)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/organizations/{organization_id}/members", response_model=list[OrganizationMemberView])
async def list_organization_members(
    organization_id: str,
    database: Database,
    actor: Actor,
) -> list[OrganizationMember]:
    await require_organization_access(database, actor, organization_id, "ADMIN")
    query = select(OrganizationMember).where(OrganizationMember.organization_id == organization_id)
    return list((await database.scalars(query.order_by(OrganizationMember.created_at))).all())


@app.post(
    "/organizations/{organization_id}/members",
    status_code=status.HTTP_201_CREATED,
    response_model=OrganizationMemberView,
)
async def add_organization_member(
    organization_id: str,
    payload: OrganizationMemberCreate,
    database: Database,
    actor: Actor,
) -> OrganizationMember:
    await require_organization_access(database, actor, organization_id, "OWNER")
    member = await database.get(OrganizationMember, (organization_id, payload.user_id))
    if member is None:
        member = OrganizationMember(organization_id=organization_id, user_id=payload.user_id, role=payload.role)
        database.add(member)
    else:
        member.role = payload.role
    await database.flush()
    await _write_audit(
        database,
        organization_id,
        actor,
        "ORGANIZATION_MEMBER_UPSERTED",
        details={"member_user_id": payload.user_id, "role": payload.role},
    )
    return member


@app.get("/projects", response_model=list[ProjectView])
async def list_projects(
    database: Database,
    actor: Actor,
    organization_id: Annotated[str | None, Query()] = None,
) -> list[Project]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(Project).where(Project.organization_id.in_(organization_ids))
    if organization_id:
        await require_organization_access(database, actor, organization_id)
        query = query.where(Project.organization_id == organization_id)
    return list((await database.scalars(query.order_by(Project.created_at.desc()))).all())


@app.post("/projects", status_code=status.HTTP_201_CREATED, response_model=ProjectView)
async def create_project(payload: ProjectCreate, database: Database, actor: Actor) -> Project:
    organization = await require_organization_access(database, actor, payload.organization_id, "MEMBER")
    name = payload.name.strip()
    if not name:
        raise HTTPException(422, "Project name cannot be blank")
    project = Project(organization_id=payload.organization_id, name=name)
    database.add(project)
    await database.flush()
    await _write_audit(database, organization.id, actor, "PROJECT_CREATED", details={"project_id": project.id})
    return project


@app.patch("/projects/{project_id}", response_model=ProjectView)
async def update_project(project_id: str, payload: ProjectUpdate, database: Database, actor: Actor) -> Project:
    project = await database.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    organization = await organization_for_project(database, actor, project.id, "MEMBER")
    if payload.name is not None:
        project.name = payload.name.strip()
    if payload.status is not None:
        project.status = payload.status
    await _write_audit(database, organization.id, actor, "PROJECT_UPDATED", details={"project_id": project.id})
    await database.flush()
    return project


@app.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: str, database: Database, actor: Actor) -> Response:
    project = await database.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    await organization_for_project(database, actor, project.id, "ADMIN")
    if await database.scalar(select(Target.id).where(Target.project_id == project.id)):
        raise HTTPException(409, "Remove the project's targets first")
    await database.delete(project)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/targets", response_model=list[TargetView])
async def list_targets(
    database: Database,
    actor: Actor,
    project_id: Annotated[str | None, Query()] = None,
) -> list[Target]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(Target).join(Project).where(Project.organization_id.in_(organization_ids))
    if project_id:
        await organization_for_project(database, actor, project_id)
        query = query.where(Target.project_id == project_id)
    return list((await database.scalars(query.order_by(Target.created_at.desc()))).all())


@app.post("/targets", status_code=status.HTTP_201_CREATED, response_model=TargetView)
async def create_target(payload: TargetCreate, database: Database, actor: Actor) -> Target:
    organization = await organization_for_project(database, actor, payload.project_id, "MEMBER")
    url = str(payload.base_url).rstrip("/")
    existing = await database.scalar(select(Target).where(Target.base_url == url))
    if existing is not None:
        raise HTTPException(409, "Target already exists")
    parsed = urlsplit(url)
    target = Target(
        project_id=payload.project_id,
        base_url=url,
        root_domain=parsed.hostname or "",
        mode=Mode.PASSIVE.value,
    )
    database.add(target)
    await database.flush()
    await _write_audit(database, organization.id, actor, "TARGET_CREATED", target_id=target.id)
    return target


@app.patch("/targets/{target_id}", response_model=TargetView)
async def update_target(target_id: str, payload: TargetUpdate, database: Database, actor: Actor) -> Target:
    target = await database.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    organization = await organization_for_target(database, actor, target.id, "MEMBER")
    if await database.scalar(select(ScanJob.id).where(ScanJob.target_id == target.id)):
        raise HTTPException(409, "A target with scan history is immutable")
    url = str(payload.base_url).rstrip("/")
    existing = await database.scalar(select(Target).where(Target.base_url == url, Target.id != target.id))
    if existing is not None:
        raise HTTPException(409, "Target already exists")
    target.base_url = url
    target.root_domain = urlsplit(url).hostname or ""
    await _write_audit(database, organization.id, actor, "TARGET_UPDATED", target_id=target.id)
    await database.flush()
    return target


@app.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: str, database: Database, actor: Actor) -> Response:
    target = await database.get(Target, target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    await organization_for_target(database, actor, target.id, "ADMIN")
    related = (
        await database.scalar(select(Scope.id).where(Scope.target_id == target.id))
        or await database.scalar(select(Authorization.id).where(Authorization.target_id == target.id))
        or await database.scalar(select(ScanJob.id).where(ScanJob.target_id == target.id))
        or await database.scalar(select(Finding.id).where(Finding.target_id == target.id))
    )
    if related:
        raise HTTPException(409, "Target has scope, authorization, scan, or finding history")
    await database.delete(target)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/scopes", response_model=list[ScopeView])
async def list_scopes(
    database: Database,
    actor: Actor,
    target_id: Annotated[str | None, Query()] = None,
) -> list[Scope]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(Scope).join(Target).join(Project).where(Project.organization_id.in_(organization_ids))
    if target_id:
        await organization_for_target(database, actor, target_id)
        query = query.where(Scope.target_id == target_id)
    return list((await database.scalars(query.order_by(Scope.id.desc()))).all())


@app.post("/scopes", status_code=status.HTTP_201_CREATED, response_model=ScopeView)
async def create_scope(payload: ScopeCreate, database: Database, actor: Actor) -> Scope:
    target = await database.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    organization = await organization_for_target(database, actor, target.id, "MEMBER")
    origin = str(payload.origin).rstrip("/")
    parsed = urlsplit(origin)
    if parsed.hostname not in {target.root_domain, f"www.{target.root_domain}"}:
        raise HTTPException(422, "Scope origin must belong to the target domain")
    scope = Scope(
        target_id=payload.target_id,
        origin=origin,
        is_excluded=payload.is_excluded,
        path_pattern=payload.path_pattern,
        allowed_verbs=["GET", "HEAD"],
    )
    database.add(scope)
    await database.flush()
    await _write_audit(database, organization.id, actor, "SCOPE_CREATED", target_id=target.id)
    return scope


@app.patch("/scopes/{scope_id}", response_model=ScopeView)
async def update_scope(scope_id: str, payload: ScopeUpdate, database: Database, actor: Actor) -> Scope:
    scope = await database.get(Scope, scope_id)
    if scope is None:
        raise HTTPException(404, "Scope not found")
    organization = await organization_for_target(database, actor, scope.target_id, "MEMBER")
    target = await database.get(Target, scope.target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    if payload.origin is not None:
        origin = str(payload.origin).rstrip("/")
        if urlsplit(origin).hostname not in {target.root_domain, f"www.{target.root_domain}"}:
            raise HTTPException(422, "Scope origin must belong to the target domain")
        scope.origin = origin
    if payload.is_excluded is not None:
        scope.is_excluded = payload.is_excluded
    if "path_pattern" in payload.model_fields_set:
        scope.path_pattern = payload.path_pattern
    await _write_audit(database, organization.id, actor, "SCOPE_UPDATED", target_id=scope.target_id)
    await database.flush()
    return scope


@app.delete("/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scope(scope_id: str, database: Database, actor: Actor) -> Response:
    scope = await database.get(Scope, scope_id)
    if scope is None:
        raise HTTPException(404, "Scope not found")
    await organization_for_target(database, actor, scope.target_id, "MEMBER")
    await database.delete(scope)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/authorizations", response_model=list[AuthorizationView])
async def list_authorizations(
    database: Database,
    actor: Actor,
    target_id: Annotated[str | None, Query()] = None,
) -> list[Authorization]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(Authorization).join(Target).join(Project).where(Project.organization_id.in_(organization_ids))
    if target_id:
        await organization_for_target(database, actor, target_id)
        query = query.where(Authorization.target_id == target_id)
    return list((await database.scalars(query.order_by(Authorization.accepted_at.desc()))).all())


@app.post("/authorizations", status_code=status.HTTP_201_CREATED, response_model=AuthorizationView)
async def create_authorization(payload: AuthorizationCreate, database: Database, actor: Actor) -> Authorization:
    target = await database.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    organization = await organization_for_target(database, actor, target.id, "MEMBER")
    valid_from = _utc(payload.valid_from)
    valid_until = _utc(payload.valid_until)
    if valid_until <= valid_from:
        raise HTTPException(422, "Authorization end must be after start")
    authorization = Authorization(
        target_id=target.id,
        representative_name=payload.representative_name.strip(),
        representative_email=payload.representative_email.strip(),
        accepted_at=datetime.now(UTC),
        valid_from=valid_from,
        valid_until=valid_until,
        active_testing=False,
        allow_mutations=False,
        allowed_verbs=["GET", "HEAD"],
    )
    database.add(authorization)
    await database.flush()
    await _write_audit(database, organization.id, actor, "AUTHORIZATION_CREATED", target_id=target.id)
    return authorization


@app.patch("/authorizations/{authorization_id}", response_model=AuthorizationView)
async def update_authorization(
    authorization_id: str,
    payload: AuthorizationUpdate,
    database: Database,
    actor: Actor,
) -> Authorization:
    authorization = await database.get(Authorization, authorization_id)
    if authorization is None:
        raise HTTPException(404, "Authorization not found")
    organization = await organization_for_target(database, actor, authorization.target_id, "MEMBER")
    valid_from = _utc(payload.valid_from or authorization.valid_from)
    valid_until = _utc(payload.valid_until or authorization.valid_until)
    if valid_until <= valid_from:
        raise HTTPException(422, "Authorization end must be after start")
    if payload.representative_name is not None:
        authorization.representative_name = payload.representative_name.strip()
    if payload.representative_email is not None:
        authorization.representative_email = payload.representative_email.strip()
    authorization.valid_from = valid_from
    authorization.valid_until = valid_until
    await _write_audit(database, organization.id, actor, "AUTHORIZATION_UPDATED", target_id=authorization.target_id)
    await database.flush()
    return authorization


@app.delete("/authorizations/{authorization_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_authorization(authorization_id: str, database: Database, actor: Actor) -> Response:
    authorization = await database.get(Authorization, authorization_id)
    if authorization is None:
        raise HTTPException(404, "Authorization not found")
    await organization_for_target(database, actor, authorization.target_id, "ADMIN")
    job_id = await database.scalar(select(ScanJob.id).where(ScanJob.authorization_id == authorization.id))
    if job_id:
        raise HTTPException(409, "Authorization is referenced by scan history")
    await database.delete(authorization)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/scan-jobs", status_code=status.HTTP_201_CREATED, response_model=ScanJobView)
async def enqueue_passive_scan(payload: ScanJobCreate, database: Database, actor: Actor) -> ScanJob:
    target = await database.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(404, "Target not found")
    organization = await organization_for_target(database, actor, target.id, "MEMBER")
    pending = await database.scalar(
        select(ScanJob).where(
            ScanJob.target_id == target.id,
            ScanJob.status.in_(["PENDING", "RUNNING"]),
        )
    )
    if pending is not None:
        raise HTTPException(409, "Target already has a pending or running scan")
    scanner_classes: list[type[Scanner]] = list(PASSIVE_SCANNERS)
    if payload.include_zap_baseline:
        if not zap_available():
            raise HTTPException(503, "OWASP ZAP Baseline is not installed locally")
        scanner_classes.append(ZapBaselineScanner)
    target_spec = TargetSpec(target.base_url, target.root_domain, target.verified, Mode.PASSIVE)
    snapshot = ScanPolicyEngine().freeze(
        target_spec,
        None,
        [scanner().to_spec() for scanner in scanner_classes],
    )
    scopes = list((await database.scalars(select(Scope).where(Scope.target_id == target.id).order_by(Scope.id))).all())
    included_origins = [item.origin for item in scopes if not item.is_excluded]
    snapshot["allowed_origins"] = list(dict.fromkeys([target.base_url, *included_origins]))
    snapshot["excluded"] = [f"{item.origin}{item.path_pattern or '*'}" for item in scopes if item.is_excluded]
    job = ScanJob(
        target_id=target.id,
        mode=Mode.PASSIVE.value,
        status="PENDING",
        policy_snapshot=snapshot,
    )
    database.add(job)
    await database.flush()
    await _write_audit(
        database,
        organization.id,
        actor,
        "PASSIVE_SCAN_ENQUEUED",
        target_id=target.id,
        details={"job_id": job.id},
    )
    return job


@app.get("/integrations/zap")
async def zap_integration_status(actor: Actor) -> dict[str, bool]:
    """Expose only local availability; no arbitrary command is accepted."""
    return {"available": zap_available()}


@app.get("/scan-jobs", response_model=list[ScanJobView])
async def list_scan_jobs(
    database: Database,
    actor: Actor,
    target_id: Annotated[str | None, Query()] = None,
) -> list[ScanJob]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(ScanJob).join(Target).join(Project).where(Project.organization_id.in_(organization_ids))
    if target_id:
        await organization_for_target(database, actor, target_id)
        query = query.where(ScanJob.target_id == target_id)
    return list((await database.scalars(query.order_by(ScanJob.created_at.desc()))).all())


@app.get("/scan-runs", response_model=list[ScanRunView])
async def list_scan_runs(database: Database, actor: Actor) -> list[ScanRun]:
    organization_ids = await visible_organization_ids(database, actor)
    query = (
        select(ScanRun)
        .join(ScanJob)
        .join(Target)
        .join(Project)
        .where(Project.organization_id.in_(organization_ids))
        .order_by(ScanRun.started_at.desc())
    )
    return list((await database.scalars(query)).all())


@app.get("/findings", response_model=list[FindingView])
async def list_findings(
    database: Database,
    actor: Actor,
    target_id: Annotated[str | None, Query()] = None,
    finding_status: Annotated[str | None, Query(alias="status")] = None,
) -> list[Finding]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(Finding).join(Target).join(Project).where(Project.organization_id.in_(organization_ids))
    if target_id:
        await organization_for_target(database, actor, target_id)
        query = query.where(Finding.target_id == target_id)
    if finding_status:
        query = query.where(Finding.status == finding_status.upper())
    return list((await database.scalars(query.order_by(Finding.created_at.desc()))).all())


@app.patch("/findings/{finding_id}", response_model=FindingView)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    database: Database,
    actor: Actor,
) -> Finding:
    finding = await database.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    organization = await organization_for_target(database, actor, finding.target_id, "MEMBER")
    finding.status = payload.status
    await _write_audit(database, organization.id, actor, "FINDING_STATUS_UPDATED", target_id=finding.target_id)
    await database.flush()
    return finding


@app.get("/findings/{finding_id}/evidence", response_model=list[EvidenceView])
async def list_finding_evidence(finding_id: str, database: Database, actor: Actor) -> list[Evidence]:
    finding = await database.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    await organization_for_target(database, actor, finding.target_id)
    query = select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.observed_at.desc())
    return list((await database.scalars(query)).all())


@app.get("/audit-logs", response_model=list[AuditLogView])
async def list_audit_logs(
    database: Database,
    actor: Actor,
    organization_id: Annotated[str | None, Query()] = None,
) -> list[AuditLog]:
    organization_ids = await visible_organization_ids(database, actor)
    query = select(AuditLog).where(AuditLog.organization_id.in_(organization_ids))
    if organization_id:
        await require_organization_access(database, actor, organization_id)
        query = query.where(AuditLog.organization_id == organization_id)
    return list((await database.scalars(query.order_by(AuditLog.occurred_at.desc()))).all())


@app.get("/reports/targets/{target_id}/executive.pdf")
async def executive_report(target_id: str, database: Database, actor: Actor) -> Response:
    report = await _report_input(target_id, database, actor)
    content = generate_pdf(report, "executive")
    filename = f"safescope-executive-{target_id[:8]}.pdf"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/reports/targets/{target_id}/technical.pdf")
async def technical_report(target_id: str, database: Database, actor: Actor) -> Response:
    report = await _report_input(target_id, database, actor)
    content = generate_pdf(report, "technical")
    filename = f"safescope-technical-{target_id[:8]}.pdf"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/reports/targets/{target_id}/proposal.md", response_class=PlainTextResponse)
async def proposal_template(target_id: str, database: Database, actor: Actor) -> str:
    report = await _report_input(target_id, database, actor)
    return proposal_markdown(
        EngagementTemplateInput(
            organization_name=report.organization_name,
            project_name=report.project_name,
            target_url=report.target_url,
            generated_at=report.created_at,
        )
    )


@app.get("/reports/targets/{target_id}/roe.md", response_class=PlainTextResponse)
async def roe_template(target_id: str, database: Database, actor: Actor) -> str:
    report = await _report_input(target_id, database, actor)
    return roe_markdown(
        EngagementTemplateInput(
            organization_name=report.organization_name,
            project_name=report.project_name,
            target_url=report.target_url,
            generated_at=report.created_at,
        )
    )


@app.get("/summary", response_model=SummaryView)
async def dashboard_summary(database: Database, actor: Actor) -> SummaryView:
    organization_ids = await visible_organization_ids(database, actor)
    target_query = select(Target).join(Project).where(Project.organization_id.in_(organization_ids))
    targets = list((await database.scalars(target_query)).all())
    target_ids = [item.id for item in targets]
    jobs = list((await database.scalars(select(ScanJob).where(ScanJob.target_id.in_(target_ids)))).all())
    findings = list((await database.scalars(select(Finding).where(Finding.target_id.in_(target_ids)))).all())
    open_findings = [item for item in findings if item.status in {"OPEN", "ACKNOWLEDGED"}]
    score = calculate_security_score(ScoreInput(item.severity, _confidence(item.confidence)) for item in open_findings)
    return SummaryView(
        score=score.value,
        deductions=score.deductions,
        open_findings=len(open_findings),
        total_findings=len(findings),
        targets=len(targets),
        pending_jobs=sum(item.status == "PENDING" for item in jobs),
        running_jobs=sum(item.status == "RUNNING" for item in jobs),
        completed_jobs=sum(item.status == "COMPLETED" for item in jobs),
    )
