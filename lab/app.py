"""Deliberately vulnerable local-only target used as SafeScope's known-answer lab."""

from __future__ import annotations

from fastapi import Cookie, FastAPI, HTTPException, Response
from pydantic import BaseModel

app = FastAPI(title="SafeScope IDOR Lab")

_PASSWORDS = {"user_a": "lab-a", "user_b": "lab-b"}
_PROFILES = {
    "user_a": {"id": "canary-user-a", "display_name": "Canary A"},
    "user_b": {"id": "canary-user-b", "display_name": "Canary B"},
}


class LoginBody(BaseModel):
    identity: str
    password: str


@app.post("/login")
async def login(payload: LoginBody, response: Response) -> dict[str, str]:
    if _PASSWORDS.get(payload.identity) != payload.password:
        raise HTTPException(401, "invalid lab credential")
    response.set_cookie("lab_session", payload.identity, httponly=True, samesite="strict")
    return {"status": "authenticated"}


@app.get("/me")
async def me(lab_session: str | None = Cookie(default=None)) -> dict[str, str]:
    if lab_session not in _PASSWORDS:
        raise HTTPException(401, "not authenticated")
    return {"identity": lab_session}


@app.get("/api/profiles/{identity}")
async def vulnerable_profile(identity: str, lab_session: str | None = Cookie(default=None)) -> dict[str, str]:
    if lab_session not in _PASSWORDS:
        raise HTTPException(401, "not authenticated")
    profile = _PROFILES.get(identity)
    if profile is None:
        raise HTTPException(404, "profile not found")
    # Deliberate lab flaw: ownership is not checked. Do not copy this route.
    return profile


@app.get("/api/secure-profiles/{identity}")
async def secure_profile(identity: str, lab_session: str | None = Cookie(default=None)) -> dict[str, str]:
    if lab_session not in _PASSWORDS:
        raise HTTPException(401, "not authenticated")
    if lab_session != identity:
        raise HTTPException(403, "forbidden")
    profile = _PROFILES.get(identity)
    if profile is None:
        raise HTTPException(404, "profile not found")
    return profile
