"""Production authentication and tenant authorization for the API."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated

import httpx
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select

from safescope_core.models import Organization, OrganizationMember, Project, Target

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class Principal:
    """Identity verified by Supabase Auth or the explicit local development mode."""

    user_id: str
    email: str | None
    production: bool


def production_mode() -> bool:
    return os.getenv("SAFESCOPE_MODE", "development").strip().lower() == "production"


async def current_principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
    """Verify bearer tokens with Supabase Auth; development has an explicit local actor."""
    if not production_mode():
        return Principal("local-developer", "local@safescope.invalid", False)
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    publishable_key = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")
    if not url or not publishable_key:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Supabase Auth is not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token required")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{url}/auth/v1/user",
                headers={"apikey": publishable_key, "Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Supabase Auth is unavailable") from error
    if response.status_code != status.HTTP_200_OK:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired session")
    payload = response.json()
    user_id = payload.get("id")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid Supabase user")
    email = payload.get("email")
    return Principal(user_id, email if isinstance(email, str) else None, True)


Actor = Annotated[Principal, Depends(current_principal)]

_ROLE_RANK = {"VIEWER": 0, "MEMBER": 1, "ADMIN": 2, "OWNER": 3}


async def require_organization_access(
    database: AsyncSession,
    actor: Principal,
    organization_id: str,
    minimum_role: str = "VIEWER",
) -> Organization:
    """Return an organization only if the actor has the required tenant role."""
    organization = await database.get(Organization, organization_id)
    if organization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if not actor.production:
        return organization
    membership = await database.get(OrganizationMember, (organization_id, actor.user_id))
    if membership is None or _ROLE_RANK.get(membership.role, -1) < _ROLE_RANK[minimum_role]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return organization


async def organization_for_project(
    database: AsyncSession,
    actor: Principal,
    project_id: str,
    minimum_role: str = "VIEWER",
) -> Organization:
    project = await database.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return await require_organization_access(database, actor, project.organization_id, minimum_role)


async def organization_for_target(
    database: AsyncSession,
    actor: Principal,
    target_id: str,
    minimum_role: str = "VIEWER",
) -> Organization:
    target = await database.get(Target, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    return await organization_for_project(database, actor, target.project_id, minimum_role)


async def visible_organization_ids(database: AsyncSession, actor: Principal) -> list[str]:
    """Return only organizations the current actor can observe."""
    if not actor.production:
        return list((await database.scalars(select(Organization.id))).all())
    query = select(OrganizationMember.organization_id).where(OrganizationMember.user_id == actor.user_id)
    return list((await database.scalars(query)).all())
