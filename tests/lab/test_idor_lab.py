"""End-to-end known-answer test for login, controls and IDOR proof."""

from __future__ import annotations

import asyncio

import httpx

from lab.app import app
from safescope_core.policy import RequestDescriptor, ResponseData
from safescope_core.vault.credential import CredentialVault, SecretString
from safescope_scanners.base import ScanContext
from safescope_scanners.razor import AuthorizationCandidate, IdorScanner
from safescope_scanners.session import HealthProbe, LoginProfile, LoginStep, SessionRuntime, SuccessPredicate


class LabChannel:
    def __init__(self) -> None:
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://lab.local")

    async def request(self, descriptor: RequestDescriptor) -> ResponseData:
        response = await self.client.request(
            descriptor.method,
            descriptor.url,
            headers=descriptor.headers,
            content=descriptor.body,
        )
        return ResponseData(response.status_code, dict(response.headers), response.content, str(response.url))

    async def aclose(self) -> None:
        await self.client.aclose()


def _profile(identity: str) -> LoginProfile:
    return LoginProfile(
        identity,
        "customer",
        (
            LoginStep(
                "POST",
                "http://lab.local/login",
                (("content-type", "application/json"),),
                f'{{"identity":"{identity}","password":"${{secret:{identity}_password}}"}}',
            ),
        ),
        SuccessPredicate((200,), "authenticated"),
        HealthProbe("http://lab.local/me", (200,), identity),
    )


def test_known_vulnerability_is_confirmed_with_negative_control() -> None:
    async def run() -> None:
        vault = CredentialVault()
        vault.put("lab-run", "user_a_password", SecretString("lab-a"))
        vault.put("lab-run", "user_b_password", SecretString("lab-b"))
        runtime = SessionRuntime("lab-run", vault, lambda _identity: LabChannel())
        await runtime.open(_profile("user_a"))
        await runtime.open(_profile("user_b"))
        try:
            candidate = AuthorizationCandidate(
                "user_a",
                "user_b",
                RequestDescriptor("GET", "http://lab.local/api/profiles/user_a"),
                RequestDescriptor("GET", "http://lab.local/api/profiles/missing"),
                RequestDescriptor("GET", "http://lab.local/api/profiles/user_a"),
                canary=True,
            )
            context = ScanContext(
                "http://lab.local",
                http=None,
                ledger=None,
                sessions=runtime,
                metadata={
                    "policy_snapshot": {"allowed_payloads": ["authorization-canary-read"]},
                    "idor_candidates": [candidate],
                },
            )
            observations = await IdorScanner().scan(context)
            assert len(observations) == 1
            assert observations[0].title == "Broken object-level authorization on test canary"
            assert observations[0].confidence == 0.98

            secure_candidate = AuthorizationCandidate(
                "user_a",
                "user_b",
                RequestDescriptor("GET", "http://lab.local/api/secure-profiles/user_a"),
                RequestDescriptor("GET", "http://lab.local/api/secure-profiles/missing"),
                RequestDescriptor("GET", "http://lab.local/api/secure-profiles/user_a"),
                canary=True,
            )
            context.metadata["idor_candidates"] = [secure_candidate]
            assert await IdorScanner().scan(context) == []
        finally:
            await runtime.aclose()
        assert vault.active_runs() == []

    asyncio.run(run())
